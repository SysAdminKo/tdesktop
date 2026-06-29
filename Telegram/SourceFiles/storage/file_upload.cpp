/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "storage/file_upload.h"

#include "api/api_editing.h"
#include "api/api_send_progress.h"
#include "core/application.h"
#include "core/core_settings.h"
#include "storage/localimageloader.h"
#include "storage/file_download.h"
#include "data/data_document.h"
#include "data/data_document_media.h"
#include "data/data_photo.h"
#include "data/data_session.h"
#include "ui/image/image_location_factory.h"
#include "history/history_item.h"
#include "history/history.h"
#include "core/file_location.h"
#include "core/application.h"
#include "core/mime_type.h"
#include "main/main_session.h"
#include "storage/storage_account.h"
#include "apiwrap.h"

namespace Storage {
namespace {

// max 1mb uploaded at the same time in each session
constexpr auto kMaxUploadPerSession = 1024 * 1024;

constexpr auto kDocumentMaxPartsCountDefault = 4000;

// 32kb for tiny document ( < 1mb )
constexpr auto kDocumentUploadPartSize0 = 32 * 1024;

// 64kb for little document ( <= 32mb )
constexpr auto kDocumentUploadPartSize1 = 64 * 1024;

// 128kb for small document ( <= 375mb )
constexpr auto kDocumentUploadPartSize2 = 128 * 1024;

// 256kb for medium document ( <= 750mb )
constexpr auto kDocumentUploadPartSize3 = 256 * 1024;

// 512kb for large document ( <= 1500mb )
constexpr auto kDocumentUploadPartSize4 = 512 * 1024;

// One part each half second, if not uploaded faster.
constexpr auto kUploadRequestInterval = crl::time(250);

// How much time without upload causes additional session kill.
constexpr auto kKillSessionTimeout = 15 * crl::time(1000);
constexpr auto kWssKillSessionTimeout = 3 * 60 * crl::time(1000);

// How much wait after session kill before killing another one.
constexpr auto kWaitForNormalizeTimeout = 8 * crl::time(1000);

constexpr auto kMaxSessionsCount = 8;
constexpr auto kFastRequestThreshold = 1 * crl::time(1000);
constexpr auto kWssFastRequestThreshold = 5 * crl::time(1000);
constexpr auto kWssSlowRequestThreshold = 30 * crl::time(1000);
constexpr auto kSlowRequestThreshold = 8 * crl::time(1000);
constexpr auto kWssInitialUploadSessions = 3;
constexpr auto kWssWarmUpFileSize = 2 * 1024 * 1024;
constexpr auto kWssWarmUpMinReadySessions = 1;
constexpr auto kWssWarmUpSettleDelay = crl::time(150);

// Request is 'fast' if it was done in less than 1s and
// (it-s size + queued before size) >= 512kb.
constexpr auto kAcceptAsFastIfTotalAtLeast = 512 * 1024;

[[nodiscard]] const char *ThumbnailFormat(const QString &mime) {
	return Core::IsMimeSticker(mime) ? "WEBP" : "JPG";
}

} // namespace

struct Uploader::Entry {
	Entry(FullMsgId itemId, const std::shared_ptr<FilePrepareResult> &file);

	void setDocSize(int64 size);
	bool setPartSize(int partSize);

	// const, but non-const for the move-assignment in the
	FullMsgId itemId;
	std::shared_ptr<FilePrepareResult> file;
	not_null<std::vector<QByteArray>*> parts;
	uint64 partsOfId = 0;

	int64 sentSize = 0;
	ushort partsSent = 0;
	ushort partsWaiting = 0;

	HashMd5 md5Hash;

	std::unique_ptr<QFile> docFile;
	int64 docSize = 0;
	int64 docSentSize = 0;
	int docPartSize = 0;
	ushort docPartsSent = 0;
	ushort docPartsCount = 0;
	ushort docPartsWaiting = 0;

};

struct Uploader::Request {
	FullMsgId itemId;
	crl::time sent = 0;
	QByteArray bytes;
	int queued = 0;
	ushort part = 0;
	uchar dcIndex = 0;
	bool docPart = false;
	bool bigPart = false;
	bool nonPremiumDelayed = false;
};

Uploader::Entry::Entry(
	FullMsgId itemId,
	const std::shared_ptr<FilePrepareResult> &file)
: itemId(itemId)
, file(file)
, parts((file->type == SendMediaType::Photo
	|| file->type == SendMediaType::Secure)
		? &file->fileparts
		: &file->thumbparts)
, partsOfId((file->type == SendMediaType::Photo
	|| file->type == SendMediaType::Secure)
		? file->id
		: file->thumbId) {
	if (file->type == SendMediaType::File
		|| file->type == SendMediaType::ThemeFile
		|| file->type == SendMediaType::Audio
		|| file->type == SendMediaType::Round) {
		setDocSize(file->filesize);
	}
}

void Uploader::Entry::setDocSize(int64 size) {
	docSize = size;
	constexpr auto limit0 = 1024 * 1024;
	constexpr auto limit1 = 32 * limit0;
	if (docSize >= limit0 || !setPartSize(kDocumentUploadPartSize0)) {
		if (docSize > limit1 || !setPartSize(kDocumentUploadPartSize1)) {
			if (!setPartSize(kDocumentUploadPartSize2)) {
				if (!setPartSize(kDocumentUploadPartSize3)) {
					setPartSize(kDocumentUploadPartSize4);
				}
			}
		}
	}
}

bool Uploader::Entry::setPartSize(int partSize) {
	docPartSize = partSize;
	docPartsCount = (docSize + docPartSize - 1) / docPartSize;
	return (docPartsCount <= kDocumentMaxPartsCountDefault);
}

Uploader::Uploader(not_null<ApiWrap*> api)
: _api(api)
, _nextTimer([=] { maybeSend(); })
, _stopSessionsTimer([=] { stopSessions(); })
, _warmUpSettleTimer([=] { maybeSend(); }) {
	const auto session = &_api->session();
	const auto &instance = _api->instance();
	instance.uploadSessionStateChanges(
	) | rpl::on_next([=](const std::pair<MTP::ShiftedDcId, int32> &change) {
		const auto &[shiftedDcId, state] = change;
		const auto index = MTP::GetDcIdShift(shiftedDcId)
			- MTP::kBaseUploadDcShift;
		if (state == MTP::ConnectedState) {
			warmUpSessionConnected(index);
			uploadSessionConnected(index);
		} else if (state == MTP::DisconnectedState) {
			uploadSessionReset(index);
		}
	}, _lifetime);
	photoReady(
	) | rpl::on_next([=](UploadedMedia &&data) {
		if (data.edit) {
			const auto item = session->data().message(data.fullId);
			Api::EditMessageWithUploadedPhoto(
				item,
				std::move(data.info),
				data.options);
		} else {
			_api->sendUploadedPhoto(
				data.fullId,
				std::move(data.info),
				data.options);
		}
	}, _lifetime);

	documentReady(
	) | rpl::on_next([=](UploadedMedia &&data) {
		if (data.edit) {
			const auto item = session->data().message(data.fullId);
			Api::EditMessageWithUploadedDocument(
				item,
				std::move(data.info),
				data.options);
		} else {
			_api->sendUploadedDocument(
				data.fullId,
				std::move(data.info),
				data.options);
		}
	}, _lifetime);

	photoProgress(
	) | rpl::on_next([=](const FullMsgId &fullId) {
		processPhotoProgress(fullId);
	}, _lifetime);

	photoFailed(
	) | rpl::on_next([=](const FullMsgId &fullId) {
		processPhotoFailed(fullId);
	}, _lifetime);

	documentProgress(
	) | rpl::on_next([=](const FullMsgId &fullId) {
		processDocumentProgress(fullId);
	}, _lifetime);

	documentFailed(
	) | rpl::on_next([=](const FullMsgId &fullId) {
		processDocumentFailed(fullId);
	}, _lifetime);

	_api->instance().nonPremiumDelayedRequests(
	) | rpl::on_next([=](mtpRequestId id) {
		const auto i = _requests.find(id);
		if (i != end(_requests)) {
			i->second.nonPremiumDelayed = true;
		}
	}, _lifetime);
}

void Uploader::processPhotoProgress(FullMsgId itemId) {
	if (const auto item = session().data().message(itemId)) {
		sendProgressUpdate(item, Api::SendProgressType::UploadPhoto);
	}
}

void Uploader::processDocumentProgress(FullMsgId itemId) {
	if (const auto item = session().data().message(itemId)) {
		const auto media = item->media();
		const auto document = media ? media->document() : nullptr;
		const auto sendAction = (document && document->isVoiceMessage())
			? Api::SendProgressType::UploadVoice
			: (document && document->isVideoMessage())
			? Api::SendProgressType::UploadRound
			: Api::SendProgressType::UploadFile;
		const auto progress = (document && document->uploading())
			? ((document->uploadingData->offset * 100)
				/ document->uploadingData->size)
			: 0;
		sendProgressUpdate(item, sendAction, progress);
	}
}

void Uploader::processPhotoFailed(FullMsgId itemId) {
	if (const auto item = session().data().message(itemId)) {
		sendProgressUpdate(item, Api::SendProgressType::UploadPhoto, -1);
	}
}

void Uploader::processDocumentFailed(FullMsgId itemId) {
	if (const auto item = session().data().message(itemId)) {
		const auto media = item->media();
		const auto document = media ? media->document() : nullptr;
		const auto sendAction = (document && document->isVoiceMessage())
			? Api::SendProgressType::UploadVoice
			: (document && document->isVideoMessage())
			? Api::SendProgressType::UploadRound
			: Api::SendProgressType::UploadFile;
		sendProgressUpdate(item, sendAction, -1);
	}
}

void Uploader::sendProgressUpdate(
		not_null<HistoryItem*> item,
		Api::SendProgressType type,
		int progress) {
	const auto history = item->history();
	auto &manager = _api->session().sendProgressManager();
	manager.update(history, type, progress);
	if (const auto replyTo = item->replyToTop()) {
		if (history->peer->isMegagroup()) {
			manager.update(history, replyTo, type, progress);
		}
	} else if (history->isForum()) {
		manager.update(history, item->topicRootId(), type, progress);
	}
	_api->session().data().requestItemRepaint(item);
}

Uploader::~Uploader() {
	clear();
}

Main::Session &Uploader::session() const {
	return _api->session();
}

FullMsgId Uploader::currentUploadId() const {
	return _queue.empty() ? FullMsgId() : _queue.front().itemId;
}

void Uploader::upload(
		FullMsgId itemId,
		const std::shared_ptr<FilePrepareResult> &file) {
	_useWssMux = useWssMux();
	const auto largeDocument = (file->type == SendMediaType::File
		|| file->type == SendMediaType::ThemeFile
		|| file->type == SendMediaType::Audio
		|| file->type == SendMediaType::Round)
		&& file->filesize >= kWssWarmUpFileSize;
	if (_useWssMux) {
		const auto warmCount = largeDocument
			? kWssInitialUploadSessions
			: 1;
		if (largeDocument || _sentPerDcIndex.empty()) {
			warmUpSessions(warmCount);
		}
	}
	if (file->type == SendMediaType::Photo) {
		const auto photo = session().data().processPhoto(
			file->photo,
			file->photoThumbs);
		photo->uploadingData = std::make_unique<Data::UploadState>(
			file->partssize);
	} else if (file->type == SendMediaType::File
		|| file->type == SendMediaType::ThemeFile
		|| file->type == SendMediaType::Audio
		|| file->type == SendMediaType::Round) {
		const auto document = file->thumb.isNull()
			? session().data().processDocument(file->document)
			: session().data().processDocument(
				file->document,
				Images::FromImageInMemory(
					file->thumb,
					ThumbnailFormat(file->filemime),
					file->thumbbytes));
		document->uploadingData = std::make_unique<Data::UploadState>(
			document->size);
		if (const auto active = document->activeMediaView()) {
			if (!file->goodThumbnail.isNull()) {
				active->setGoodThumbnail(std::move(file->goodThumbnail));
			}
			if (!file->thumb.isNull()) {
				active->setThumbnail(file->thumb);
			}
		}
		if (!file->goodThumbnailBytes.isEmpty()) {
			document->owner().cache().putIfEmpty(
				document->goodThumbnailCacheKey(),
				Storage::Cache::Database::TaggedValue(
					std::move(file->goodThumbnailBytes),
					Data::kImageCacheTag));
		}
		if (!file->content.isEmpty()) {
			document->setDataAndCache(file->content);
		}
		if (!file->filepath.isEmpty()) {
			document->setLocation(Core::FileLocation(file->filepath));
		} else if (!file->content.isEmpty()
			&& !document->saveToCache()
			&& !document->useStreamingLoader()
			&& Core::App().canSaveFileWithoutAskingForPath()) {
			const auto path = DocumentFileNameForSave(document);
			if (!path.isEmpty()) {
				auto f = QFile(path);
				if (f.open(QIODevice::WriteOnly)
					&& f.write(file->content) == file->content.size()) {
					f.close();
					document->setLocation(Core::FileLocation(path));
					session().local().writeFileLocation(
						document->mediaKey(),
						Core::FileLocation(path));
				}
			}
		}
		if (file->type == SendMediaType::ThemeFile) {
			document->checkWallPaperProperties();
		}
		if (file->videoCover) {
			session().data().processPhoto(
				file->videoCover->photo,
				file->videoCover->photoThumbs);
		}
	}
	_queue.push_back({ itemId, file });
	if (!_nextTimer.isActive()) {
		maybeSend();
	}
}

void Uploader::failed(FullMsgId itemId) {
	const auto i = ranges::find(_queue, itemId, &Entry::itemId);
	if (i != end(_queue)) {
		const auto entry = std::move(*i);
		_queue.erase(i);
		notifyFailed(entry);
	} else if (const auto coverId = _videoIdToCoverId.take(itemId)) {
		if (const auto video = _videoWaitingCover.take(*coverId)) {
			const auto document = session().data().document(video->id);
			if (document->uploading()) {
				document->status = FileUploadFailed;
			}
			_documentFailed.fire_copy(video->fullId);
		}
		failed(*coverId);
	} else if (const auto video = _videoWaitingCover.take(itemId)) {
		_videoIdToCoverId.remove(video->fullId);
		const auto document = session().data().document(video->id);
		if (document->uploading()) {
			document->status = FileUploadFailed;
		}
		_documentFailed.fire_copy(video->fullId);
	}
	cancelRequests(itemId);
	maybeFinishFront();

	crl::on_main(this, [=] {
		maybeSend();
	});
}

void Uploader::notifyFailed(const Entry &entry) {
	const auto type = entry.file->type;
	if (type == SendMediaType::Photo) {
		_photoFailed.fire_copy(entry.itemId);
	} else if (type == SendMediaType::File
		|| type == SendMediaType::ThemeFile
		|| type == SendMediaType::Audio
		|| type == SendMediaType::Round) {
		const auto document = session().data().document(entry.file->id);
		if (document->uploading()) {
			document->status = FileUploadFailed;
		}
		_documentFailed.fire_copy(entry.itemId);
	} else if (type == SendMediaType::Secure) {
		_secureFailed.fire_copy(entry.itemId);
	} else {
		Unexpected("Type in Uploader::failed.");
	}
}

void Uploader::stopSessions() {
	if (ranges::any_of(_sentPerDcIndex, rpl::mappers::_1 != 0)) {
		_stopSessionsTimer.callOnce(killSessionTimeout());
	} else {
		for (auto i = 0; i != int(_sentPerDcIndex.size()); ++i) {
			_api->instance().stopSession(MTP::uploadDcId(i));
		}
		_sentPerDcIndex.clear();
		_sessionTracks.clear();
		_dcIndicesWithFastRequests.clear();
		_warmUpTarget = 0;
		_warmUpConnected.clear();
		_warmUpReadyLogged = false;
		_warmUpSettleUntil = 0;
	}
}

bool Uploader::useWssMux() const {
	const auto &proxy = Core::App().settings().proxy();
	return proxy.isEnabled()
		&& proxy.selected().type == MTP::ProxyData::Type::WebSocket;
}

crl::time Uploader::killSessionTimeout() const {
	return _useWssMux ? kWssKillSessionTimeout : kKillSessionTimeout;
}

crl::time Uploader::fastRequestThreshold() const {
	return _useWssMux ? kWssFastRequestThreshold : kFastRequestThreshold;
}

void Uploader::warmUpSessions(int count) {
	if (!_useWssMux) {
		return;
	}
	const auto normalized = std::clamp(count, 1, kMaxSessionsCount);
	_warmUpTarget = std::max(_warmUpTarget, normalized);
	tryWarmUpSessions();
}

bool Uploader::isWarmUpReady() const {
	if (!_warmUpTarget) {
		return true;
	}
	const auto minReady = std::min(
		_warmUpTarget,
		kWssWarmUpMinReadySessions);
	for (auto i = 0; i != minReady; ++i) {
		if (!_warmUpConnected.contains(i)) {
			return false;
		}
	}
	return true;
}

bool Uploader::isWarmUpComplete() const {
	if (!_warmUpTarget) {
		return true;
	}
	for (auto i = 0; i != _warmUpTarget; ++i) {
		if (!_warmUpConnected.contains(i)) {
			return false;
		}
	}
	return true;
}

void Uploader::onWarmUpReady() {
	if (_warmUpReadyLogged) {
		return;
	}
	_warmUpReadyLogged = true;
	DEBUG_LOG(("Upload warm-up session 0 connected, ready."));
	scheduleWarmUpSettle();
	maybeSend();
}

void Uploader::scheduleWarmUpSettle() {
	if (_warmUpSettleUntil) {
		return;
	}
	_warmUpSettleUntil = crl::now() + kWssWarmUpSettleDelay;
	if (!_warmUpSettleTimer.isActive()) {
		_warmUpSettleTimer.callOnce(kWssWarmUpSettleDelay);
	}
}

bool Uploader::isUploadSessionWarmReady(int index) const {
	if (!_useWssMux || !_warmUpTarget || index >= _warmUpTarget) {
		return true;
	} else if (index < kWssWarmUpMinReadySessions) {
		return _warmUpConnected.contains(index);
	}
	return isWarmUpReady();
}

void Uploader::markUploadSessionWarm(int index) {
	ensureSessionTracks(index + 1);
	auto &track = _sessionTracks[index];
	track.warm = true;
	track.coldStartAt = 0;
	track.connectAt = 0;
}

void Uploader::warmSessionDisconnected(int index) {
	if (!_useWssMux || !_warmUpTarget || index >= _warmUpTarget) {
		return;
	} else if (!_warmUpConnected.remove(index)) {
		return;
	}
	tryWarmUpSessions();
}

void Uploader::tryWarmUpSessions() {
	if (!_warmUpTarget) {
		return;
	}
	auto &instance = _api->instance();
	for (auto i = 0; i != _warmUpTarget; ++i) {
		if (_warmUpConnected.contains(i)) {
			continue;
		}
		const auto shiftedDcId = MTP::uploadDcId(i);
		if (instance.dcstate(shiftedDcId) == MTP::ConnectedState) {
			_warmUpConnected.emplace(i);
			markUploadSessionWarm(i);
			continue;
		}
		instance.sendAnything(shiftedDcId);
	}
	if (isWarmUpReady()) {
		onWarmUpReady();
	}
	if (isWarmUpComplete()) {
		DEBUG_LOG(("Upload warm-up sessions 0..%1 connected."
			).arg(_warmUpTarget - 1));
	}
	if (!_queue.empty()) {
		maybeSend();
	}
}

void Uploader::warmUpSessionConnected(int index) {
	if (!_useWssMux || index >= _warmUpTarget) {
		return;
	}
	if (!_warmUpConnected.emplace(index).second) {
		return;
	}
	markUploadSessionWarm(index);
	if (isWarmUpReady()) {
		onWarmUpReady();
	}
	if (isWarmUpComplete()) {
		DEBUG_LOG(("Upload warm-up sessions 0..%1 connected."
			).arg(_warmUpTarget - 1));
	}
	maybeSend();
}

void Uploader::ensureSessionTracks(int count) {
	if (int(_sessionTracks.size()) < count) {
		_sessionTracks.resize(count);
	}
}

void Uploader::uploadRequestSent(int index) {
	ensureSessionTracks(index + 1);
	auto &track = _sessionTracks[index];
	if (track.warm) {
		return;
	} else if (_warmUpConnected.contains(index)) {
		track.warm = true;
		return;
	}
	const auto now = crl::now();
	track.coldStartAt = now;
	track.connectAt = 0;
	if (_api->instance().dcstate(MTP::uploadDcId(index)) == MTP::ConnectedState) {
		track.connectAt = now;
	}
}

void Uploader::uploadSessionConnected(int index) {
	ensureSessionTracks(index + 1);
	auto &track = _sessionTracks[index];
	if (track.warm || !track.coldStartAt || track.connectAt) {
		return;
	}
	track.connectAt = crl::now();
	DEBUG_LOG(("Upload (%1) cold start: connect %2 ms"
		).arg(index
		).arg(track.connectAt - track.coldStartAt));
}

void Uploader::uploadSessionReset(int index) {
	if (index < 0 || index >= int(_sessionTracks.size())) {
		return;
	}
	auto &track = _sessionTracks[index];
	track.coldStartAt = 0;
	track.connectAt = 0;
	track.warm = false;
	warmSessionDisconnected(index);
}

QByteArray Uploader::readDocPart(not_null<Entry*> entry) {
	const auto checked = [&](QByteArray result) {
		if ((entry->file->type == SendMediaType::File
			|| entry->file->type == SendMediaType::ThemeFile
			|| entry->file->type == SendMediaType::Audio
			|| entry->file->type == SendMediaType::Round)
			&& entry->docSize <= kUseBigFilesFrom) {
			entry->md5Hash.feed(result.data(), result.size());
		}
		if (result.isEmpty()
			|| (result.size() > entry->docPartSize)
			|| ((result.size() < entry->docPartSize
				&& entry->docPartsSent + 1 != entry->docPartsCount))) {
			return QByteArray();
		}
		return result;
	};
	auto &content = entry->file->content;
	if (!content.isEmpty()) {
		const auto offset = entry->docPartsSent * entry->docPartSize;
		return checked(content.mid(offset, entry->docPartSize));
	} else if (!entry->docFile) {
		const auto filepath = entry->file->filepath;
		entry->docFile = std::make_unique<QFile>(filepath);
		if (!entry->docFile->open(QIODevice::ReadOnly)) {
			return QByteArray();
		}
	}
	return checked(entry->docFile->read(entry->docPartSize));
}

bool Uploader::canAddDcIndex() const {
	const auto count = int(_sentPerDcIndex.size());
	if (count >= kMaxSessionsCount) {
		return false;
	}
	const auto fast = int(_dcIndicesWithFastRequests.size());
	if (_useWssMux && count < kWssInitialUploadSessions) {
		return true;
	}
	return count == fast;
}

std::optional<uchar> Uploader::chooseDcIndexForNextRequest(
		const base::flat_set<uchar> &used) {
	for (auto i = 0, count = int(_sentPerDcIndex.size()); i != count; ++i) {
		if (!_sentPerDcIndex[i]
			&& !used.contains(i)
			&& isUploadSessionWarmReady(i)) {
			return i;
		}
	}
	if (canAddDcIndex()) {
		const auto result = int(_sentPerDcIndex.size());
		_sentPerDcIndex.push_back(0);
		_dcIndicesWithFastRequests.clear();
		_latestDcIndexAdded = crl::now();
		if (_useWssMux) {
			warmUpSessions(result + 1);
		}

		DEBUG_LOG(("Uploader: Added dc index %1.").arg(result));
		if (isUploadSessionWarmReady(result)) {
			return result;
		}
	}
	auto result = std::optional<int>();
	for (auto i = 0, count = int(_sentPerDcIndex.size()); i != count; ++i) {
		if (!used.contains(i)
			&& isUploadSessionWarmReady(i)
			&& (!result.has_value()
				|| _sentPerDcIndex[i] < _sentPerDcIndex[*result])) {
			result = i;
		}
	}
	return result;
}

Uploader::Entry *Uploader::chooseEntryForNextRequest() {
	if (!_pendingFromRemovedDcIndices.empty()) {
		const auto itemId = _pendingFromRemovedDcIndices.front().itemId;
		const auto i = ranges::find(_queue, itemId, &Entry::itemId);
		Assert(i != end(_queue));
		return &*i;
	}

	for (auto i = begin(_queue); i != end(_queue); ++i) {
		if (i->partsSent < i->parts->size()
			|| i->docPartsSent < i->docPartsCount) {
			return &*i;
		}
	}
	return nullptr;
}

auto Uploader::sendPart(not_null<Entry*> entry, uchar dcIndex)
-> SendResult {
	return !_pendingFromRemovedDcIndices.empty()
		? sendPendingPart(entry, dcIndex)
		: (entry->partsSent < entry->parts->size())
		? sendSlicedPart(entry, dcIndex)
		: sendDocPart(entry, dcIndex);
}

template <typename Prepared>
void Uploader::sendPreparedRequest(Prepared &&prepared, Request &&request) {
	auto &sentInSession = _sentPerDcIndex[request.dcIndex];
	const auto queued = sentInSession;
	if (queued == 0) {
		uploadRequestSent(request.dcIndex);
	}
	sentInSession += int(request.bytes.size());

	const auto requestId = _api->request(
		std::move(prepared)
	).done([=](const MTPBool &result, mtpRequestId requestId) {
		partLoaded(result, requestId);
	}).fail([=](const MTP::Error &error, mtpRequestId requestId) {
		partFailed(error, requestId);
	}).toDC(MTP::uploadDcId(request.dcIndex)).send();

	request.sent = crl::now();
	request.queued = queued;
	_requests.emplace(requestId, std::move(request));
}

auto Uploader::sendPendingPart(not_null<Entry*> entry, uchar dcIndex)
-> SendResult {
	Expects(!_pendingFromRemovedDcIndices.empty());
	Expects(_pendingFromRemovedDcIndices.front().itemId == entry->itemId);

	auto request = std::move(_pendingFromRemovedDcIndices.front());
	_pendingFromRemovedDcIndices.erase(begin(_pendingFromRemovedDcIndices));

	const auto part = request.part;
	const auto bytes = request.bytes;
	request.dcIndex = dcIndex;
	if (request.bigPart) {
		sendPreparedRequest(MTPupload_SaveBigFilePart(
			MTP_long(entry->file->id),
			MTP_int(part),
			MTP_int(entry->docPartsCount),
			MTP_bytes(bytes)
		), std::move(request));
	} else {
		const auto id = request.docPart ? entry->file->id : entry->partsOfId;
		sendPreparedRequest(MTPupload_SaveFilePart(
			MTP_long(id),
			MTP_int(part),
			MTP_bytes(bytes)
		), std::move(request));
	}
	return SendResult::Success;
}

auto Uploader::sendDocPart(not_null<Entry*> entry, uchar dcIndex)
-> SendResult {
	const auto itemId = entry->itemId;
	const auto alreadySent = _sentPerDcIndex[dcIndex];
	const auto willProbablyBeSent = entry->docPartSize;
	if (alreadySent + willProbablyBeSent > kMaxUploadPerSession) {
		return SendResult::DcIndexFull;
	}

	Assert(entry->docPartsSent < entry->docPartsCount);

	const auto partBytes = readDocPart(entry);
	if (partBytes.isEmpty()) {
		failed(itemId);
		return SendResult::Failed;
	}
	const auto part = entry->docPartsSent++;
	++entry->docPartsWaiting;

	const auto send = [&](auto &&request, bool big) {
		sendPreparedRequest(std::move(request), {
			.itemId = itemId,
			.bytes = partBytes,
			.part = part,
			.dcIndex = dcIndex,
			.docPart = true,
			.bigPart = big,
		});
	};
	if (entry->docSize > kUseBigFilesFrom) {
		send(MTPupload_SaveBigFilePart(
			MTP_long(entry->file->id),
			MTP_int(part),
			MTP_int(entry->docPartsCount),
			MTP_bytes(partBytes)
		), true);
	} else {
		send(MTPupload_SaveFilePart(
			MTP_long(entry->file->id),
			MTP_int(part),
			MTP_bytes(partBytes)
		), false);
	}
	return SendResult::Success;
}

auto Uploader::sendSlicedPart(not_null<Entry*> entry, uchar dcIndex)
-> SendResult {
	const auto itemId = entry->itemId;
	const auto alreadySent = _sentPerDcIndex[dcIndex];
	const auto willBeSent = entry->parts->at(entry->partsSent).size();
	if (alreadySent + willBeSent >= kMaxUploadPerSession) {
		return SendResult::DcIndexFull;
	}

	++entry->partsWaiting;
	const auto index = entry->partsSent++;
	const auto partBytes = entry->parts->at(index);
	sendPreparedRequest(MTPupload_SaveFilePart(
		MTP_long(entry->partsOfId),
		MTP_int(index),
		MTP_bytes(partBytes)
	), {
		.itemId = itemId,
		.bytes = partBytes,
		.dcIndex = dcIndex,
	});
	return SendResult::Success;
}

void Uploader::maybeSend() {
	const auto stopping = _stopSessionsTimer.isActive();
	if (_queue.empty()) {
		if (!stopping) {
			_stopSessionsTimer.callOnce(killSessionTimeout());
		}
		_pausedId = FullMsgId();
		return;
	} else if (_pausedId) {
		return;
	} else if (stopping) {
		_stopSessionsTimer.cancel();
	} else if (_useWssMux && _warmUpTarget && !isWarmUpReady()) {
		return;
	} else if (_useWssMux
		&& _warmUpSettleUntil
		&& crl::now() < _warmUpSettleUntil) {
		return;
	}

	auto usedDcIndices = base::flat_set<uchar>();
	while (true) {
		const auto maybeDcIndex = chooseDcIndexForNextRequest(usedDcIndices);
		if (!maybeDcIndex.has_value()) {
			break;
		}
		const auto dcIndex = *maybeDcIndex;
		while (true) {
			const auto entry = chooseEntryForNextRequest();
			if (!entry) {
				return;
			}
			const auto result = sendPart(entry, dcIndex);
			if (result == SendResult::DcIndexFull) {
				return;
			} else if (result == SendResult::Success) {
				break;
			}
			// If this entry failed, we try the next one.
		}
		if (_sentPerDcIndex[dcIndex] >= kAcceptAsFastIfTotalAtLeast) {
			usedDcIndices.emplace(dcIndex);
		}
	}
	if (usedDcIndices.empty()) {
		_nextTimer.cancel();
	} else {
		_nextTimer.callOnce(kUploadRequestInterval);
	}
}

void Uploader::cancel(FullMsgId itemId) {
	failed(itemId);
}

void Uploader::cancelAll() {
	while (!_queue.empty()) {
		failed(_queue.front().itemId);
	}
	clear();
	unpause();
}

void Uploader::pause(FullMsgId itemId) {
	_pausedId = itemId;
}

void Uploader::unpause() {
	_pausedId = FullMsgId();
	maybeSend();
}

void Uploader::cancelRequests(FullMsgId itemId) {
	for (auto i = begin(_requests); i != end(_requests);) {
		if (i->second.itemId == itemId) {
			const auto bytes = int(i->second.bytes.size());
			_sentPerDcIndex[i->second.dcIndex] -= bytes;
			_api->request(i->first).cancel();
			i = _requests.erase(i);
		} else {
			++i;
		}
	}
	_pendingFromRemovedDcIndices.erase(ranges::remove(
		_pendingFromRemovedDcIndices,
		itemId,
		&Request::itemId
	), end(_pendingFromRemovedDcIndices));
}

void Uploader::cancelAllRequests() {
	for (const auto &[requestId, request] : base::take(_requests)) {
		_api->request(requestId).cancel();
	}
	ranges::fill(_sentPerDcIndex, 0);
}

void Uploader::clear() {
	_queue.clear();
	cancelAllRequests();
	stopSessions();
	_stopSessionsTimer.cancel();
}

Uploader::Request Uploader::finishRequest(mtpRequestId requestId) {
	const auto taken = _requests.take(requestId);
	Assert(taken.has_value());

	_sentPerDcIndex[taken->dcIndex] -= int(taken->bytes.size());
	return *taken;
}

void Uploader::partLoaded(const MTPBool &result, mtpRequestId requestId) {
	const auto request = finishRequest(requestId);

	const auto bytes = int(request.bytes.size());
	const auto itemId = request.itemId;

	if (mtpIsFalse(result)) { // failed to upload current file
		failed(itemId);
		return;
	}

	const auto i = ranges::find(_queue, itemId, &Entry::itemId);
	Assert(i != end(_queue));
	auto &entry = *i;

	const auto now = crl::now();
	const auto duration = now - request.sent;
	const auto fastThreshold = fastRequestThreshold();
	const auto slowThreshold = _useWssMux
		? kWssSlowRequestThreshold
		: kSlowRequestThreshold;
	const auto fast = (duration < fastThreshold);
	const auto slowish = !fast;
	const auto slow = (duration >= slowThreshold);

	if (request.dcIndex < int(_sessionTracks.size())) {
		auto &track = _sessionTracks[request.dcIndex];
		if (!track.warm && track.coldStartAt) {
			const auto total = now - track.coldStartAt;
			const auto connect = track.connectAt
				? (track.connectAt - track.coldStartAt)
				: crl::time(0);
			DEBUG_LOG(("Upload (%1) cold start: connect %2 ms, first part %3 ms, total %4 ms"
				).arg(request.dcIndex
				).arg(connect
				).arg(duration
				).arg(total));
			track.warm = true;
			track.coldStartAt = 0;
			track.connectAt = 0;
		}
	}

	if (slowish) {
		if (!_useWssMux) {
			_dcIndicesWithFastRequests.clear();
		}
		if (slow) {
			if (_useWssMux) {
				DEBUG_LOG(("Uploader: Slow request, clear fast records."));
			} else {
				const auto elapsed = (now - _latestDcIndexRemoved);
				const auto remove = (elapsed >= kWaitForNormalizeTimeout);
				if (remove && _sentPerDcIndex.size() > 1) {
					DEBUG_LOG(("Uploader: Slow request, removing dc index."));
					removeDcIndex();
					_latestDcIndexRemoved = now;
				} else {
					DEBUG_LOG(("Uploader: Slow request, clear fast records."));
				}
			}
		} else {
			DEBUG_LOG(("Uploader: Slow-ish request, clear fast records."));
		}
	} else if (_useWssMux
		|| (request.sent > _latestDcIndexAdded
			&& (request.queued + bytes >= kAcceptAsFastIfTotalAtLeast))) {
		if (_dcIndicesWithFastRequests.emplace(request.dcIndex).second) {
			DEBUG_LOG(("Uploader: Mark %1 of %2 as fast."
				).arg(request.dcIndex
				).arg(_sentPerDcIndex.size()));
		}
	}

	if (request.docPart) {
		--entry.docPartsWaiting;
		entry.docSentSize += bytes;
	} else {
		--entry.partsWaiting;
		entry.sentSize += bytes;
	}

	if (entry.file->type == SendMediaType::Photo) {
		const auto photo = session().data().photo(entry.file->id);
		if (photo->uploading()) {
			photo->uploadingData->size = entry.file->partssize;
			photo->uploadingData->offset = entry.sentSize;
		}
		_photoProgress.fire_copy(itemId);
	} else if (entry.file->type == SendMediaType::File
		|| entry.file->type == SendMediaType::ThemeFile
		|| entry.file->type == SendMediaType::Audio
		|| entry.file->type == SendMediaType::Round) {
		const auto document = session().data().document(entry.file->id);
		if (document->uploading()) {
			document->uploadingData->offset = std::min(
				document->uploadingData->size,
				entry.docSentSize);
		}
		_documentProgress.fire_copy(itemId);
	} else if (entry.file->type == SendMediaType::Secure) {
		_secureProgress.fire_copy({
			.fullId = itemId,
			.offset = entry.sentSize,
			.size = entry.file->partssize,
		});
	}
	if (request.nonPremiumDelayed) {
		_nonPremiumDelays.fire_copy(itemId);
	}

	if (!_queue.empty() && itemId == _queue.front().itemId) {
		maybeFinishFront();
	}
	maybeSend();
}

void Uploader::removeDcIndex() {
	Expects(_sentPerDcIndex.size() > 1);

	const auto dcIndex = int(_sentPerDcIndex.size()) - 1;
	for (auto i = begin(_requests); i != end(_requests);) {
		if (i->second.dcIndex == dcIndex) {
			const auto bytes = int(i->second.bytes.size());
			_sentPerDcIndex[dcIndex] -= bytes;
			_api->request(i->first).cancel();
			_pendingFromRemovedDcIndices.push_back(std::move(i->second));
			i = _requests.erase(i);
		} else {
			++i;
		}
	}
	Assert(_sentPerDcIndex.back() == 0);
	_sentPerDcIndex.pop_back();
	if (int(_sessionTracks.size()) > dcIndex) {
		_sessionTracks.pop_back();
	}
	_dcIndicesWithFastRequests.remove(dcIndex);
	_api->instance().stopSession(MTP::uploadDcId(dcIndex));
	DEBUG_LOG(("Uploader: Removed dc index %1.").arg(dcIndex));
}

void Uploader::maybeFinishFront() {
	while (!_queue.empty()) {
		const auto &entry = _queue.front();
		if (entry.partsSent >= entry.parts->size()
			&& entry.docPartsSent >= entry.docPartsCount
			&& !entry.partsWaiting
			&& !entry.docPartsWaiting) {
			finishFront();
		} else {
			break;
		}
	}
}

void Uploader::finishFront() {
	Expects(!_queue.empty());

	auto entry = std::move(_queue.front());
	_queue.erase(_queue.begin());

	const auto options = entry.file
		? entry.file->to.options
		: Api::SendOptions();
	const auto edit = entry.file &&
		entry.file->to.replaceMediaOf;
	const auto attachedStickers = entry.file
		? entry.file->attachedStickers
		: std::vector<MTPInputDocument>();
	if (entry.file->type == SendMediaType::Photo) {
		auto photoFilename = entry.file->filename;
		if (!photoFilename.endsWith(u".jpg"_q, Qt::CaseInsensitive)) {
			// Server has some extensions checking for inputMediaUploadedPhoto,
			// so force the extension to be .jpg anyway. It doesn't matter,
			// because the filename from inputFile is not used anywhere.
			photoFilename += u".jpg"_q;
		}
		const auto md5 = entry.file->filemd5;
		const auto file = MTP_inputFile(
			MTP_long(entry.file->id),
			MTP_int(entry.parts->size()),
			MTP_string(photoFilename),
			MTP_bytes(md5));
		auto ready = UploadedMedia{
			.id = entry.file->id,
			.fullId = entry.itemId,
			.info = {
				.file = file,
				.attachedStickers = attachedStickers,
			},
			.options = options,
			.edit = edit,
		};
		const auto i = _videoWaitingCover.find(entry.itemId);
		if (i != end(_videoWaitingCover)) {
			uploadCoverAsPhoto(i->second.fullId, std::move(ready));
		} else {
			_photoReady.fire(std::move(ready));
		}
	} else if (entry.file->type == SendMediaType::File
		|| entry.file->type == SendMediaType::ThemeFile
		|| entry.file->type == SendMediaType::Audio
		|| entry.file->type == SendMediaType::Round) {
		QByteArray docMd5(32, Qt::Uninitialized);
		hashMd5Hex(entry.md5Hash.result(), docMd5.data());

		const auto file = (entry.docSize > kUseBigFilesFrom)
			? MTP_inputFileBig(
				MTP_long(entry.file->id),
				MTP_int(entry.docPartsCount),
				MTP_string(entry.file->filename))
			: MTP_inputFile(
				MTP_long(entry.file->id),
				MTP_int(entry.docPartsCount),
				MTP_string(entry.file->filename),
				MTP_bytes(docMd5));
		const auto thumb = [&]() -> std::optional<MTPInputFile> {
			if (entry.parts->empty()) {
				return std::nullopt;
			}
			const auto thumbFilename = entry.file->thumbname;
			const auto thumbMd5 = entry.file->thumbmd5;
			return MTP_inputFile(
				MTP_long(entry.file->thumbId),
				MTP_int(entry.parts->size()),
				MTP_string(thumbFilename),
				MTP_bytes(thumbMd5));
		}();
		auto ready = UploadedMedia{
			.id = entry.file->id,
			.fullId = entry.itemId,
			.info = {
				.file = file,
				.thumb = thumb,
				.attachedStickers = attachedStickers,
				.forceFile = entry.file->forceFile,
			},
			.options = options,
			.edit = edit,
		};
		if (entry.file->videoCover) {
			uploadVideoCover(std::move(ready), entry.file->videoCover);
		} else {
			_documentReady.fire(std::move(ready));
		}
	} else if (entry.file->type == SendMediaType::Secure) {
		_secureReady.fire({
			entry.itemId,
			entry.file->id,
			int(entry.parts->size()),
		});
	}
}

void Uploader::partFailed(const MTP::Error &error, mtpRequestId requestId) {
	const auto request = finishRequest(requestId);
	failed(request.itemId);
}

void Uploader::uploadVideoCover(
		UploadedMedia &&video,
		std::shared_ptr<FilePrepareResult> videoCover) {
	const auto coverId = FullMsgId(
		videoCover->to.peer,
		session().data().nextLocalMessageId());
	_videoIdToCoverId.emplace(video.fullId, coverId);
	_videoWaitingCover.emplace(coverId, std::move(video));

	upload(coverId, videoCover);
}

void Uploader::uploadCoverAsPhoto(
		FullMsgId videoId,
		UploadedMedia &&cover) {
	const auto coverId = cover.fullId;
	_api->request(MTPmessages_UploadMedia(
		MTP_flags(0),
		MTPstring(), // business_connection_id
		session().data().peer(videoId.peer)->input(),
		MTP_inputMediaUploadedPhoto(
			MTP_flags(0),
			cover.info.file,
			MTP_vector<MTPInputDocument>(0),
			MTP_int(0),
			MTPInputDocument()) // video
	)).done([=](const MTPMessageMedia &result) {
		result.match([&](const MTPDmessageMediaPhoto &data) {
			const auto photo = data.vphoto();
			if (!photo || photo->type() != mtpc_photo) {
				failed(coverId);
				return;
			}
			const auto &fields = photo->c_photo();
			if (const auto coverId = _videoIdToCoverId.take(videoId)) {
				if (auto video = _videoWaitingCover.take(*coverId)) {
					video->info.videoCover = MTP_inputPhoto(
						fields.vid(),
						fields.vaccess_hash(),
						fields.vfile_reference());
					_documentReady.fire(std::move(*video));
				}
			}
		}, [&](const auto &) {
			failed(coverId);
		});
	}).fail([=] {
		failed(coverId);
	}).send();
}

} // namespace Storage
