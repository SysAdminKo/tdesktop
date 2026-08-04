#Requires -Version 5.1
<#
.SYNOPSIS
  Emulate Telegram Desktop DPI: ClientHello burst / paced / delay sweep.

.DESCRIPTION
  Success = GotServerHello (TLS handshake type 0x02). Alert/any-reply is NOT pass.

.EXAMPLE
  # Replay pcap Hello, find min delay between Hellos (start 1s, step -75ms):
  powershell -NoProfile -ExecutionPolicy Bypass -File tools\dpi_hello_burst_emu.ps1 `
    -TGHelloFile tools\Dumps\tg_hello_from_pcap.bin -Mode Sweep

.EXAMPLE
  # Fixed pace between sequential Hellos:
  .\tools\dpi_hello_burst_emu.ps1 -TGHelloFile tools\Dumps\tg_hello_from_pcap.bin `
    -Mode Paced -PaceMs 500 -BurstCount 10

.EXAMPLE
  # Simultaneous burst (old behavior):
  .\tools\dpi_hello_burst_emu.ps1 -TGHelloFile tools\Dumps\tg_hello_from_pcap.bin -Mode Burst

.EXAMPLE
  # TG pcap vs Chrome vs Firefox vs SslStream:
  .\tools\dpi_hello_burst_emu.ps1 -TGHelloFile tools\Dumps\tg_hello_from_pcap.bin `
    -ChromeHelloFile tools\Dumps\chrome_hello_from_pcap.bin `
    -FirefoxHelloFile tools\Dumps\firefox_hello_from_pcap.bin `
    -Mode Compare -BurstCount 11 -TrialsPerDelay 16 -CsvOut dpi_compare.csv

.EXAMPLE
  # Bucket using Firefox PQ Hello from FF.pcapng:
  .\tools\dpi_hello_burst_emu.ps1 -TGHelloFile tools\Dumps\firefox_hello_from_pcap.bin `
    -Mode Bucket -RoundDelayMs 160000 -CsvOut dpi_bucket_ff.csv
#>
[CmdletBinding()]
param(
	[string] $Ip = '94.103.169.67',
	[int] $Port = 4443,
	[ValidateSet('Burst', 'Paced', 'Sweep', 'Compare', 'Bucket')]
	[string] $Mode = 'Burst',
	[int] $BurstCount = 11,
	[int] $Rounds = 3,
	[int] $RoundDelayMs = 30000,
	[int] $PaceMs = 1000,
	[int] $SweepStartMs = 1000,
	[int] $SweepStepMs = 75,
	[int] $SweepMinMs = 0,
	[int] $TrialsPerDelay = 8,
	[double] $PassRate = 1.0,
	[int] $CompareSafePaceMs = 1000,
	[int] $CompareHotPaceMs = 850,
	[int] $BucketProbeMax = 20,
	[int] $BucketFillPaceMs = 50,
	[int] $BucketCapacityRounds = 3,
	[string] $BucketCapacityPacesMs = '50,200,500,850',
	[int] $BucketRecoverMaxMs = 30000,
	[int] $BucketRecoverStepMs = 1000,
	[switch] $BucketProbeDuringRecover,
	[string] $BucketSustainPacesMs = '1200,1000,900,850',
	[int] $BucketSustainCount = 20,
	[switch] $BucketSustainBinary,
	[string] $Sni = 'pro.willdomarket.com',
	[string] $TGHelloFile = 'tools\Dumps\tg_hello_from_pcap.bin',
	[string] $ChromeHelloFile = 'tools\Dumps\chrome_hello_from_pcap.bin',
	[string] $FirefoxHelloFile = 'tools\Dumps\firefox_hello_from_pcap.bin',
	[int] $ConnectTimeoutMs = 3000,
	[int] $WaitMs = 3000,
	[string] $CsvOut = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

if (-not ('DpiHelloEmuV7' -as [type])) {
	Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Threading;

public static class DpiHelloEmuV7 {
	static readonly Random Rng = new Random();

	public static string BytesToHex(byte[] buf, int offset, int count) {
		if (buf == null || count <= 0) return "";
		var sb = new StringBuilder(count * 2);
		int end = Math.Min(buf.Length, offset + count);
		for (int i = offset; i < end; i++) sb.Append(buf[i].ToString("x2"));
		return sb.ToString();
	}

	public static string ClassifyReply(byte[] buf, int n) {
		if (n <= 0 || buf == null) return "none";
		// Scan whole buffer: ServerHello may follow CCS/other records.
		for (int k = 0; k + 5 < n; k++) {
			if (buf[k] == 0x16 && buf[k + 5] == 0x02) return "server-hello";
		}
		byte t = buf[0];
		if (t == 0x15) {
			string desc = "alert";
			if (n >= 7) desc += "-" + buf[6];
			return desc;
		}
		if (t == 0x17) return "appdata";
		if (t == 0x14) return "ccs";
		if (t == 0x16) {
			if (n >= 6) {
				byte hs = buf[5];
				if (hs == 0x0b) return "handshake-cert";
				if (hs == 0x0e) return "handshake-hello-done";
				if (hs == 0x04) return "handshake-newsession";
				return "handshake-0x" + hs.ToString("x2");
			}
			return "handshake";
		}
		return "other-0x" + t.ToString("x2");
	}

	public static byte[] BuildClientHello(string sni) {
		var random = new byte[32];
		Rng.NextBytes(random);
		var x25519 = new byte[32];
		Rng.NextBytes(x25519);

		// Clean TLS1.3-style ClientHello (no GREASE). Must parse cleanly in Wireshark.
		ushort[] ciphers = new ushort[] {
			0x1301, 0x1302, 0x1303,
			0xc02b, 0xc02f, 0xc02c, 0xc030,
			0xcca9, 0xcca8, 0xc013, 0xc014,
			0x009c, 0x009d, 0x002f, 0x0035
		};

		var sniHost = Encoding.ASCII.GetBytes(sni);
		var extensions = new List<byte>();

		// server_name (0)
		{
			var body = new List<byte>();
			body.Add(0x00); // host_name
			body.Add((byte)(sniHost.Length >> 8));
			body.Add((byte)sniHost.Length);
			body.AddRange(sniHost);
			var list = new List<byte>();
			list.Add((byte)(body.Count >> 8));
			list.Add((byte)body.Count);
			list.AddRange(body);
			WriteExt(extensions, 0x0000, list);
		}
		// supported_groups (10): x25519, secp256r1, secp384r1
		WriteExt(extensions, 0x000a, new byte[] {
			0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18
		});
		// signature_algorithms (13)
		WriteExt(extensions, 0x000d, new byte[] {
			0x00, 0x0c,
			0x04, 0x03, 0x08, 0x04, 0x04, 0x01,
			0x05, 0x03, 0x08, 0x05, 0x05, 0x01
		});
		// supported_versions (43): TLS1.3, TLS1.2
		WriteExt(extensions, 0x002b, new byte[] {
			0x04, 0x03, 0x04, 0x03, 0x03
		});
		// key_share (51): single x25519 — ext len = 2+2+2+32 = 38 = 0x0026 (NOT 0x002b)
		{
			var body = new List<byte>();
			body.Add(0x00); body.Add(0x24); // client_shares length 36
			body.Add(0x00); body.Add(0x1d); // group x25519
			body.Add(0x00); body.Add(0x20); // key length 32
			body.AddRange(x25519);
			WriteExt(extensions, 0x0033, body);
		}
		// renegotiation_info (0xff01)
		WriteExt(extensions, 0xff01, new byte[] { 0x00 });
		// session_ticket (35) empty
		WriteExt(extensions, 0x0023, new byte[] { });

		var hs = new List<byte>();
		hs.Add(0x03); hs.Add(0x03);
		hs.AddRange(random);
		hs.Add(0x00); // session_id empty
		hs.Add((byte)((ciphers.Length * 2) >> 8));
		hs.Add((byte)(ciphers.Length * 2));
		foreach (var c in ciphers) {
			hs.Add((byte)(c >> 8));
			hs.Add((byte)c);
		}
		hs.Add(0x01); hs.Add(0x00); // compression null
		hs.Add((byte)(extensions.Count >> 8));
		hs.Add((byte)extensions.Count);
		hs.AddRange(extensions);

		var handshake = new List<byte>();
		handshake.Add(0x01);
		handshake.Add((byte)((hs.Count >> 16) & 0xff));
		handshake.Add((byte)((hs.Count >> 8) & 0xff));
		handshake.Add((byte)(hs.Count & 0xff));
		handshake.AddRange(hs);

		var record = new List<byte>();
		record.Add(0x16);
		record.Add(0x03); record.Add(0x01);
		record.Add((byte)(handshake.Count >> 8));
		record.Add((byte)handshake.Count);
		record.AddRange(handshake);

		string err;
		if (!ValidateClientHello(record.ToArray(), out err)) {
			throw new Exception("BuildClientHello self-check failed: " + err);
		}
		return record.ToArray();
	}


	public static string GetClientHelloSni(byte[] hello) {
		string err;
		if (!ValidateClientHello(hello, out err)) return "";
		int o = 9 + 2 + 32;
		int sidLen = hello[o++];
		o += sidLen;
		int csLen = (hello[o] << 8) | hello[o + 1];
		o += 2 + csLen;
		int compLen = hello[o++];
		o += compLen;
		int extLen = (hello[o] << 8) | hello[o + 1];
		o += 2;
		int end = o + extLen;
		while (o + 4 <= end) {
			int et = (hello[o] << 8) | hello[o + 1];
			int el = (hello[o + 2] << 8) | hello[o + 3];
			int eb = o + 4;
			if (et == 0x0000 && el >= 5) {
				int hostLen = (hello[eb + 3] << 8) | hello[eb + 4];
				if (eb + 5 + hostLen <= end) {
					return Encoding.ASCII.GetString(hello, eb + 5, hostLen);
				}
				return "";
			}
			o = eb + el;
		}
		return "";
	}

	public static byte[] ReplaceSni(byte[] hello, string sni) {
		if (hello == null) throw new ArgumentNullException("hello");
		if (string.IsNullOrEmpty(sni)) return hello;
		string err;
		if (!ValidateClientHello(hello, out err)) {
			throw new Exception("ReplaceSni: invalid ClientHello: " + err);
		}
		var newHost = Encoding.ASCII.GetBytes(sni);
		int o = 9 + 2 + 32;
		int sidLen = hello[o++];
		o += sidLen;
		int csLen = (hello[o] << 8) | hello[o + 1];
		o += 2 + csLen;
		int compLen = hello[o++];
		o += compLen;
		int extLenOff = o;
		int extLen = (hello[o] << 8) | hello[o + 1];
		o += 2;
		int extStart = o;
		int extEnd = extStart + extLen;
		int i = extStart;
		while (i + 4 <= extEnd) {
			int et = (hello[i] << 8) | hello[i + 1];
			int el = (hello[i + 2] << 8) | hello[i + 3];
			int eb = i + 4;
			if (et == 0x0000) {
				if (el < 5 || hello[eb + 2] != 0x00) {
					throw new Exception("ReplaceSni: unsupported server_name layout");
				}
				int listLen = (hello[eb] << 8) | hello[eb + 1];
				int hostLen = (hello[eb + 3] << 8) | hello[eb + 4];
				int hostOff = eb + 5;
				if (hostOff + hostLen > extEnd) {
					throw new Exception("ReplaceSni: host overflows extension");
				}
				string old = Encoding.ASCII.GetString(hello, hostOff, hostLen);
				if (old == sni) return hello;
				int delta = newHost.Length - hostLen;
				var result = new byte[hello.Length + delta];
				Buffer.BlockCopy(hello, 0, result, 0, hostOff);
				Buffer.BlockCopy(newHost, 0, result, hostOff, newHost.Length);
				Buffer.BlockCopy(
					hello, hostOff + hostLen,
					result, hostOff + newHost.Length,
					hello.Length - hostOff - hostLen);
				result[eb + 3] = (byte)(newHost.Length >> 8);
				result[eb + 4] = (byte)newHost.Length;
				int newListLen = listLen + delta;
				result[eb] = (byte)(newListLen >> 8);
				result[eb + 1] = (byte)newListLen;
				int newEl = el + delta;
				result[i + 2] = (byte)(newEl >> 8);
				result[i + 3] = (byte)newEl;
				int newExtLen = extLen + delta;
				result[extLenOff] = (byte)(newExtLen >> 8);
				result[extLenOff + 1] = (byte)newExtLen;
				int hsLen = ((hello[6] << 16) | (hello[7] << 8) | hello[8]) + delta;
				result[6] = (byte)((hsLen >> 16) & 0xff);
				result[7] = (byte)((hsLen >> 8) & 0xff);
				result[8] = (byte)(hsLen & 0xff);
				int recLen = ((hello[3] << 8) | hello[4]) + delta;
				result[3] = (byte)(recLen >> 8);
				result[4] = (byte)recLen;
				if (!ValidateClientHello(result, out err)) {
					throw new Exception("ReplaceSni: patched hello invalid: " + err);
				}
				return result;
			}
			i = eb + el;
		}
		throw new Exception("ReplaceSni: server_name extension not found");
	}

	static void WriteExt(List<byte> dst, int type, IList<byte> body) {
		dst.Add((byte)(type >> 8));
		dst.Add((byte)type);
		dst.Add((byte)(body.Count >> 8));
		dst.Add((byte)body.Count);
		for (int i = 0; i < body.Count; i++) dst.Add(body[i]);
	}

	public static bool ValidateClientHello(byte[] h, out string error) {
		error = "";
		if (h == null || h.Length < 50 || h[0] != 0x16) {
			error = "not tls handshake record";
			return false;
		}
		int recLen = (h[3] << 8) | h[4];
		if (h.Length != 5 + recLen) {
			error = "record length mismatch";
			return false;
		}
		if (h[5] != 0x01) {
			error = "not clienthello";
			return false;
		}
		int hsLen = (h[6] << 16) | (h[7] << 8) | h[8];
		if (hsLen != h.Length - 9) {
			error = "handshake length mismatch";
			return false;
		}
		var body = new byte[hsLen];
		Buffer.BlockCopy(h, 9, body, 0, hsLen);
		int o = 34; // after ver+random
		int sidLen = body[o];
		o += 1 + sidLen;
		int csLen = (body[o] << 8) | body[o + 1];
		o += 2 + csLen;
		int compLen = body[o];
		o += 1 + compLen;
		int extLen = (body[o] << 8) | body[o + 1];
		o += 2;
		if (extLen != body.Length - o) {
			error = "extensions length mismatch";
			return false;
		}
		int i = 0;
		var seen = new HashSet<int>();
		while (i + 4 <= extLen) {
			int et = (body[o + i] << 8) | body[o + i + 1];
			int el = (body[o + i + 2] << 8) | body[o + i + 3];
			if (i + 4 + el > extLen) {
				error = "extension overflow type=0x" + et.ToString("x4");
				return false;
			}
			if (seen.Contains(et)) {
				error = "duplicate extension type=0x" + et.ToString("x4");
				return false;
			}
			seen.Add(et);
			i += 4 + el;
		}
		if (i != extLen) {
			error = "extensions trailing bytes";
			return false;
		}
		if (!seen.Contains(0x0000) || !seen.Contains(0x002b) || !seen.Contains(0x0033)) {
			error = "missing required extensions";
			return false;
		}
		return true;
	}

	static void ReadExact(NetworkStream stream, byte[] buf, int offset, int count, int timeoutMs) {
		stream.ReadTimeout = timeoutMs;
		int got = 0;
		while (got < count) {
			int n = stream.Read(buf, offset + got, count - got);
			if (n <= 0) throw new Exception("eof while reading TLS record");
			got += n;
		}
	}

	// Capture a real OS/Schannel ClientHello via SslStream to localhost.
	public static byte[] CaptureSslStreamClientHello(string sni, int timeoutMs) {
		var listener = new TcpListener(IPAddress.Loopback, 0);
		listener.Start();
		var port = ((IPEndPoint)listener.LocalEndpoint).Port;
		Exception clientEx = null;
		var clientDone = new ManualResetEvent(false);
		var clientThread = new Thread(() => {
			try {
				using (var client = new TcpClient()) {
					client.Connect(IPAddress.Loopback, port);
					using (var ssl = new SslStream(client.GetStream(), false, (s, c, ch, e) => true)) {
						try {
							ssl.AuthenticateAsClient(sni);
						} catch {
						}
					}
				}
			} catch (Exception ex) {
				clientEx = ex;
			} finally {
				clientDone.Set();
			}
		});
		clientThread.IsBackground = true;
		clientThread.Start();

		byte[] hello;
		try {
			if (!listener.Server.Poll(timeoutMs * 1000, SelectMode.SelectRead)) {
				throw new Exception("ssl capture accept timeout");
			}
			using (var server = listener.AcceptTcpClient()) {
				var stream = server.GetStream();
				var hdr = new byte[5];
				ReadExact(stream, hdr, 0, 5, timeoutMs);
				if (hdr[0] != 0x16) {
					throw new Exception("ssl capture: first byte not Handshake");
				}
				int len = (hdr[3] << 8) | hdr[4];
				if (len < 4 || len > 16384) {
					throw new Exception("ssl capture: bad record len " + len);
				}
				var body = new byte[len];
				ReadExact(stream, body, 0, len, timeoutMs);
				if (body[0] != 0x01) {
					throw new Exception("ssl capture: not ClientHello hs type");
				}
				hello = new byte[5 + len];
				Buffer.BlockCopy(hdr, 0, hello, 0, 5);
				Buffer.BlockCopy(body, 0, hello, 5, len);
			}
		} finally {
			try { listener.Stop(); } catch {}
			clientDone.WaitOne(timeoutMs);
		}
		if (hello == null || hello.Length < 50) {
			var msg = "ssl capture failed";
			if (clientEx != null) msg += ": " + clientEx.Message;
			throw new Exception(msg);
		}
		return hello;
	}

	public class Attempt {
		public int Index;
		public bool TcpOk;
		public bool HelloSent;
		public bool GotServerHello;
		public bool GotAnyReply;
		public int TcpMs;
		public int ReplyMs;
		public int ReplyBytes;
		public int PaceMs;
		public string ReplyKind = "";
		public string ReplyHex = "";
		public string Error = "";
	}

	static Attempt RunOne(
		string ip, int port, int index, byte[] hello,
		int connectTimeoutMs, int waitMs, int paceMs
	) {
		var a = new Attempt { Index = index, PaceMs = paceMs };
		TcpClient client = null;
		var swTcp = System.Diagnostics.Stopwatch.StartNew();
		try {
			client = new TcpClient();
			var ar = client.BeginConnect(ip, port, null, null);
			if (!ar.AsyncWaitHandle.WaitOne(connectTimeoutMs)) {
				a.Error = "tcp-timeout";
				a.TcpMs = connectTimeoutMs;
				try { client.Close(); } catch {}
				return a;
			}
			client.EndConnect(ar);
			a.TcpOk = true;
			a.TcpMs = (int)swTcp.ElapsedMilliseconds;
		} catch (Exception ex) {
			a.Error = "tcp:" + ex.Message;
			a.TcpMs = (int)swTcp.ElapsedMilliseconds;
			try { if (client != null) client.Close(); } catch {}
			return a;
		}

		var swHello = System.Diagnostics.Stopwatch.StartNew();
		NetworkStream stream = null;
		try {
			stream = client.GetStream();
			stream.Write(hello, 0, hello.Length);
			stream.Flush();
			a.HelloSent = true;
		} catch (Exception ex) {
			a.Error = "hello:" + ex.Message;
			try { client.Close(); } catch {}
			return a;
		}

		var buf = new byte[8192];
		var deadline = DateTime.UtcNow.AddMilliseconds(waitMs);
		while (DateTime.UtcNow < deadline) {
			try {
				if (!stream.DataAvailable) {
					System.Threading.Thread.Sleep(5);
					continue;
				}
				int n = stream.Read(buf, 0, buf.Length);
				if (n <= 0) continue;
				a.GotAnyReply = true;
				a.ReplyMs = (int)swHello.ElapsedMilliseconds;
				a.ReplyBytes = n;
				a.ReplyKind = ClassifyReply(buf, n);
				a.ReplyHex = BytesToHex(buf, 0, Math.Min(n, 16));
				a.GotServerHello = (a.ReplyKind == "server-hello");
				break;
			} catch (Exception ex) {
				a.Error = "read:" + ex.Message;
				break;
			}
		}
		if (a.HelloSent && !a.GotAnyReply && string.IsNullOrEmpty(a.Error)) {
			a.Error = "no-reply";
			a.ReplyKind = "none";
			a.ReplyMs = waitMs;
		}
		try { client.Close(); } catch {}
		return a;
	}

	public static Attempt[] RunPaced(
		string ip, int port, int count,
		byte[] hello,
		int connectTimeoutMs, int waitMs,
		int paceMs
	) {
		var results = new Attempt[count];
		for (int i = 0; i < count; i++) {
			results[i] = RunOne(ip, port, i, hello, connectTimeoutMs, waitMs, paceMs);
			if (i + 1 < count && paceMs > 0) {
				System.Threading.Thread.Sleep(paceMs);
			}
		}
		return results;
	}

	public static Attempt[] RunBurst(
		string ip, int port, int count,
		byte[] hello,
		int connectTimeoutMs, int waitMs
	) {
		var clients = new TcpClient[count];
		var asyncs = new IAsyncResult[count];
		var swConnect = new System.Diagnostics.Stopwatch[count];
		var results = new Attempt[count];
		for (int i = 0; i < count; i++) {
			results[i] = new Attempt { Index = i, PaceMs = 0 };
			clients[i] = new TcpClient();
			swConnect[i] = System.Diagnostics.Stopwatch.StartNew();
			asyncs[i] = clients[i].BeginConnect(ip, port, null, null);
		}

		var deadline = DateTime.UtcNow.AddMilliseconds(connectTimeoutMs);
		var pending = new HashSet<int>();
		for (int i = 0; i < count; i++) pending.Add(i);
		while (pending.Count > 0 && DateTime.UtcNow < deadline) {
			var done = new List<int>();
			foreach (var i in pending) {
				if (!asyncs[i].IsCompleted) continue;
				done.Add(i);
				try {
					clients[i].EndConnect(asyncs[i]);
					results[i].TcpOk = true;
					results[i].TcpMs = (int)swConnect[i].ElapsedMilliseconds;
				} catch (Exception ex) {
					results[i].Error = "tcp:" + ex.Message;
					results[i].TcpMs = (int)swConnect[i].ElapsedMilliseconds;
					try { clients[i].Close(); } catch {}
					clients[i] = null;
				}
			}
			foreach (var i in done) pending.Remove(i);
			if (pending.Count > 0) System.Threading.Thread.Sleep(1);
		}
		foreach (var i in pending) {
			results[i].Error = "tcp-timeout";
			results[i].TcpMs = connectTimeoutMs;
			try { clients[i].Close(); } catch {}
			clients[i] = null;
		}

		var swHello = System.Diagnostics.Stopwatch.StartNew();
		var streams = new NetworkStream[count];
		for (int i = 0; i < count; i++) {
			if (clients[i] == null || !results[i].TcpOk) continue;
			try {
				streams[i] = clients[i].GetStream();
				streams[i].Write(hello, 0, hello.Length);
				streams[i].Flush();
				results[i].HelloSent = true;
			} catch (Exception ex) {
				results[i].Error = "hello:" + ex.Message;
				try { clients[i].Close(); } catch {}
				clients[i] = null;
				streams[i] = null;
			}
		}

		var waitDeadline = DateTime.UtcNow.AddMilliseconds(waitMs);
		var buf = new byte[8192];
		var waiting = new HashSet<int>();
		for (int i = 0; i < count; i++) {
			if (results[i].HelloSent) waiting.Add(i);
		}
		while (waiting.Count > 0 && DateTime.UtcNow < waitDeadline) {
			var done = new List<int>();
			foreach (var i in waiting) {
				try {
					if (streams[i] == null || !streams[i].DataAvailable) continue;
					int n = streams[i].Read(buf, 0, buf.Length);
					if (n <= 0) continue;
					results[i].GotAnyReply = true;
					results[i].ReplyMs = (int)swHello.ElapsedMilliseconds;
					results[i].ReplyBytes = n;
					results[i].ReplyKind = ClassifyReply(buf, n);
					results[i].ReplyHex = BytesToHex(buf, 0, Math.Min(n, 16));
					results[i].GotServerHello = (results[i].ReplyKind == "server-hello");
					done.Add(i);
				} catch (Exception ex) {
					results[i].Error = "read:" + ex.Message;
					done.Add(i);
				}
			}
			foreach (var i in done) waiting.Remove(i);
			if (waiting.Count > 0) System.Threading.Thread.Sleep(5);
		}
		foreach (var i in waiting) {
			if (string.IsNullOrEmpty(results[i].Error)) results[i].Error = "no-reply";
			results[i].ReplyKind = "none";
			results[i].ReplyMs = waitMs;
		}
		for (int i = 0; i < count; i++) {
			try { if (clients[i] != null) clients[i].Close(); } catch {}
		}
		return results;
	}
}
'@
}

function Resolve-HelloBytesFromFile {
	param([string] $Path, [string] $Label)
	if (-not $Path) { throw "$Label path is empty" }
	$file = $Path
	if (-not [System.IO.Path]::IsPathRooted($file)) {
		$file = Join-Path (Get-Location) $file
	}
	if (-not (Test-Path -LiteralPath $file)) {
		throw "$Label not found: $file"
	}
	$bytes = [System.IO.File]::ReadAllBytes($file)
	if ($bytes.Length -lt 6 -or $bytes[0] -ne 0x16) {
		throw "$Label does not look like a TLS record: $file"
	}
	$fromFile = [DpiHelloEmuV7]::GetClientHelloSni($bytes)
	if ($Sni -and $fromFile -ne $Sni) {
		Write-Host ("{0}: rewrite SNI '{1}' -> '{2}'" -f $Label, $fromFile, $Sni) -ForegroundColor DarkCyan
		$bytes = [DpiHelloEmuV7]::ReplaceSni($bytes, $Sni)
	}
	return ,@($bytes, $file)
}

function Test-LooksLikeTelegramHello {
	param([byte[]] $Hello)
	if ($Hello.Length -lt 1500) { return $false }
	$ascii = [System.Text.Encoding]::ASCII.GetString($Hello)
	if ($Sni -and $ascii.Contains($Sni)) { return $true }
	if ($ascii.Contains('pro.willdomarket.com')) { return $true }
	# TG fake-TLS uses 32-byte session_id and ~1.2KB key_share
	if ($Hello.Length -ge 9) {
		$bodyStart = 9
		if ($Hello.Length -gt $bodyStart + 35 -and $Hello[$bodyStart + 34] -eq 32) {
			return $true
		}
	}
	return $false
}

function Resolve-HelloBytes {
	if ($TGHelloFile) {
		$pair = Resolve-HelloBytesFromFile -Path $TGHelloFile -Label 'TGHelloFile'
		return ,$pair[0]
	}
	return ,[DpiHelloEmuV7]::BuildClientHello($Sni)
}

function Convert-AttemptsToRows {
	param(
		$Attempts,
		[int] $Round,
		[int] $WallMs,
		[int] $PaceMs,
		[string] $Phase
	)
	$rows = New-Object System.Collections.Generic.List[object]
	foreach ($a in $Attempts) {
		$status = if ($a.GotServerHello) { 'SERVER-HELLO' }
			elseif ($a.GotAnyReply) { 'REPLY' }
			elseif ($a.HelloSent) { 'HELLO-NO-REPLY' }
			elseif ($a.TcpOk) { 'TCP-ONLY' }
			else { 'TCP-FAIL' }
		$color = if ($a.GotServerHello) { 'Green' }
			elseif ($a.GotAnyReply) { 'Yellow' }
			else { 'Red' }
		Write-Host ("[{0}] {1} kind={2} tcp={3}ms reply={4}ms n={5} hex={6} {7}" -f `
			$a.Index, $status, $a.ReplyKind, $a.TcpMs, $a.ReplyMs, $a.ReplyBytes, $a.ReplyHex, $a.Error) `
			-ForegroundColor $color
		$rows.Add([pscustomobject]@{
			Mode           = $Mode
			Phase          = $Phase
			Round          = $Round
			PaceMs         = $PaceMs
			Index          = $a.Index
			Ip             = $Ip
			HelloSource    = $script:helloSource
			TcpOk          = $a.TcpOk
			HelloSent      = $a.HelloSent
			GotAnyReply    = $a.GotAnyReply
			GotServerHello = $a.GotServerHello
			ReplyKind      = $a.ReplyKind
			ReplyHex       = $a.ReplyHex
			ReplyBytes     = $a.ReplyBytes
			TcpMs          = $a.TcpMs
			ReplyMs        = $a.ReplyMs
			Error          = $a.Error
			WallMs         = $WallMs
		}) | Out-Null
	}
	return $rows
}

function Get-AttemptStats {
	param($Attempts)
	$hello = 0; $reply = 0; $sh = 0; $tcp = 0; $noReply = 0; $alert = 0
	$kinds = @{}
	foreach ($a in $Attempts) {
		if ($a.TcpOk) { $tcp++ }
		if ($a.HelloSent) { $hello++ }
		if ($a.GotAnyReply) { $reply++ }
		if ($a.GotServerHello) { $sh++ }
		if ($a.HelloSent -and -not $a.GotAnyReply) { $noReply++ }
		$k = if ($a.ReplyKind) { $a.ReplyKind } else { 'none' }
		if ($k -like 'alert*') { $alert++ }
		if (-not $kinds.ContainsKey($k)) { $kinds[$k] = 0 }
		$kinds[$k]++
	}
	$shRate = if ($hello -gt 0) { [double]$sh / $hello } else { 0.0 }
	$noReplyRate = if ($hello -gt 0) { [double]$noReply / $hello } else { 0.0 }
	return [pscustomobject]@{
		TcpOk = $tcp; HelloSent = $hello; Reply = $reply; ServerHello = $sh
		NoReply = $noReply; Alert = $alert
		ServerHelloRate = $shRate; NoReplyRate = $noReplyRate; Kinds = $kinds
	}
}

function Write-AttemptStats {
	param($Stats, [int] $WallMs, [int] $Count)
	$kinds = ($Stats.Kinds.GetEnumerator() | Sort-Object Name | ForEach-Object { "{0}={1}" -f $_.Key, $_.Value }) -join ' '
	$shPct = [int][math]::Round(100.0 * $Stats.ServerHelloRate)
	$nrPct = [int][math]::Round(100.0 * $Stats.NoReplyRate)
	Write-Host ("Wall={0}ms  TcpOk={1}/{2}  HelloSent={3}  Reply={4}  ServerHello={5} ({6}%)  NoReply={7} ({8}%)" -f `
		$WallMs, $Stats.TcpOk, $Count, $Stats.HelloSent, $Stats.Reply, $Stats.ServerHello, $shPct, `
		$Stats.NoReply, $nrPct) -ForegroundColor Yellow
	Write-Host ("ReplyKinds: {0}" -f $kinds) -ForegroundColor DarkCyan
	Write-Host "Pass criterion: ServerHello only (alert/other reply = fail). DPI drop signature: NoReply." -ForegroundColor DarkGray
}

function Invoke-HelloScenario {
	param(
		[string] $Label,
		[byte[]] $Hello,
		[string] $HelloTag,
		[string] $Scenario,
		[int] $Count,
		[int] $PaceMs,
		[switch] $Burst
	)
	$script:helloSource = $HelloTag
	Write-Host ""
	Write-Host ("=== [{0}] {1}  hello={2}  n={3} pace={4} ===" -f `
		$Label, $Scenario, $HelloTag, $Count, $(if ($Burst) { 'BURST' } else { "$PaceMs ms" })) -ForegroundColor Cyan
	$sw = [System.Diagnostics.Stopwatch]::StartNew()
	if ($Burst) {
		$attempts = [DpiHelloEmuV7]::RunBurst($Ip, $Port, $Count, $Hello, $ConnectTimeoutMs, $WaitMs)
	} else {
		$attempts = [DpiHelloEmuV7]::RunPaced($Ip, $Port, $Count, $Hello, $ConnectTimeoutMs, $WaitMs, $PaceMs)
	}
	$wall = [int]$sw.ElapsedMilliseconds
	$stats = Get-AttemptStats $attempts
	$paceVal = if ($Burst) { 0 } else { $PaceMs }
	$rows = Convert-AttemptsToRows -Attempts $attempts -Round 0 -WallMs $wall -PaceMs $paceVal -Phase $Scenario
	foreach ($row in $rows) {
		$row | Add-Member -NotePropertyName HelloTag -NotePropertyValue $HelloTag -Force
		$row | Add-Member -NotePropertyName Scenario -NotePropertyValue $Scenario -Force
		$all.Add($row) | Out-Null
	}
	Write-AttemptStats $stats $wall $Count
	return [pscustomobject]@{
		Label = $Label; Scenario = $Scenario; HelloTag = $HelloTag
		Stats = $stats; WallMs = $wall; Count = $Count; PaceMs = $paceVal
	}
}

function Wait-DpiCold {
	param([byte[]] $Hello, [string] $Phase)
	Write-Host ("Cold-start gate: idle {0}ms then require 1x ServerHello..." -f $RoundDelayMs) -ForegroundColor DarkYellow
	Start-Sleep -Milliseconds $RoundDelayMs
	$attempts = [DpiHelloEmuV7]::RunPaced($Ip, $Port, 1, $Hello, $ConnectTimeoutMs, $WaitMs, 0)
	$a = $attempts[0]
	$rows = Convert-AttemptsToRows -Attempts $attempts -Round 0 -WallMs 0 -PaceMs 0 -Phase $Phase
	foreach ($row in $rows) { $all.Add($row) | Out-Null }
	if (-not $a.GotServerHello) {
		Write-Host ("Cold gate FAIL kind={0} - extra idle {1}ms..." -f $a.ReplyKind, $RoundDelayMs) -ForegroundColor Red
		Start-Sleep -Milliseconds $RoundDelayMs
		$attempts = [DpiHelloEmuV7]::RunPaced($Ip, $Port, 1, $Hello, $ConnectTimeoutMs, $WaitMs, 0)
		$a = $attempts[0]
		$rows = Convert-AttemptsToRows -Attempts $attempts -Round 0 -WallMs 0 -PaceMs 0 -Phase ($Phase + '-retry')
		foreach ($row in $rows) { $all.Add($row) | Out-Null }
		if (-not $a.GotServerHello) {
			throw "DPI still blocked after 2x RoundDelayMs. Raise -RoundDelayMs (try 180000+) and rerun."
		}
	}
	Write-Host "Cold gate OK (ServerHello)." -ForegroundColor Green
	# Small settle so the gate probe itself is not counted in the next burst window.
	Start-Sleep -Milliseconds ([math]::Max(2000, [int]($RoundDelayMs / 10)))
}

function Measure-DpiCapacityStreak {
	param([byte[]] $Hello, [int] $FillPaceMs, [int] $Round, [string] $Phase)
	$okStreak = 0
	$hitDrop = $false
	for ($i = 0; $i -lt $BucketProbeMax; $i++) {
		$sw = [System.Diagnostics.Stopwatch]::StartNew()
		$attempts = [DpiHelloEmuV7]::RunPaced($Ip, $Port, 1, $Hello, $ConnectTimeoutMs, $WaitMs, 0)
		$wall = [int]$sw.ElapsedMilliseconds
		$a = $attempts[0]
		$rows = Convert-AttemptsToRows -Attempts $attempts -Round $Round -WallMs $wall -PaceMs $FillPaceMs -Phase $Phase
		foreach ($row in $rows) { $all.Add($row) | Out-Null }
		if ($a.GotServerHello) {
			$okStreak++
			Write-Host ("  [{0}] SH streak={1}" -f $i, $okStreak) -ForegroundColor Green
		} else {
			$hitDrop = $true
			Write-Host ("  [{0}] DROP kind={1} after {2} SH" -f $i, $a.ReplyKind, $okStreak) -ForegroundColor Red
			break
		}
		if ($FillPaceMs -gt 0 -and ($i + 1) -lt $BucketProbeMax) {
			Start-Sleep -Milliseconds $FillPaceMs
		}
	}
	if (-not $hitDrop) {
		Write-Host ("  No drop within probeMax={0}" -f $BucketProbeMax) -ForegroundColor Yellow
	}
	return $okStreak
}

function Get-MedianInt {
	param([int[]] $Values)
	if (-not $Values -or $Values.Count -eq 0) { return 0 }
	$s = $Values | Sort-Object
	return [int]($s[[int](($s.Count - 1) / 2)])
}

$tgHello = $null
$chromeHello = $null
$chromeHelloSource = ''
$ffHello = $null
$ffHelloSource = ''
$sslHello = $null
$helloBytes = $null

function Resolve-OptionalHelloFile([string] $Path, [string] $Label) {
	if (-not $Path) { return $null, '' }
	$full = if ([IO.Path]::IsPathRooted($Path)) { $Path } else { Join-Path (Get-Location) $Path }
	if (-not (Test-Path -LiteralPath $full)) {
		return $null, ''
	}
	$pair = Resolve-HelloBytesFromFile -Path $Path -Label $Label
	return $pair[0], ("{0}:{1}" -f $Label, $pair[1])
}

if ($Mode -eq 'Compare') {
	if (-not $TGHelloFile) {
		throw "Mode Compare requires -TGHelloFile (Telegram ClientHello from pcap)."
	}
	$tgHello = Resolve-HelloBytes

	$chromePath = $ChromeHelloFile
	if ($chromePath -and (Test-Path -LiteralPath $(if ([IO.Path]::IsPathRooted($chromePath)) { $chromePath } else { Join-Path (Get-Location) $chromePath }))) {
		$pair = Resolve-HelloBytesFromFile -Path $chromePath -Label 'ChromeHelloFile'
		$chromeHello = $pair[0]
		$chromeHelloSource = "chrome:$($pair[1])"
		if (Test-LooksLikeTelegramHello $chromeHello) {
			Write-Host ""
			Write-Host ("NOTE: ChromeHello is large + SNI {0} (PQ/MLKEM-class Hello)." -f ([DpiHelloEmuV7]::GetClientHelloSni($chromeHello))) -ForegroundColor DarkYellow
			Write-Host "  TG fake-TLS deliberately mimics Chrome, so size/ext set can look similar." -ForegroundColor DarkYellow
			Write-Host "  Bytes differ (GREASE/order/keys). Compare still valid: real Chrome vs TG." -ForegroundColor DarkYellow
			Write-Host ""
		}
	} else {
		Write-Host ("ChromeHelloFile missing ({0}) - falling back to crafted BuildClientHello." -f $ChromeHelloFile) -ForegroundColor Yellow
		$chromeHello = [DpiHelloEmuV7]::BuildClientHello($Sni)
		$chromeHelloSource = "crafted BuildClientHello"
	}

	$ffHello, $ffHelloSource = Resolve-OptionalHelloFile $FirefoxHelloFile 'FirefoxHelloFile'
	if ($ffHello) {
		Write-Host ("Firefox hello: {0} ({1} B) from FF.pcapng" -f $ffHelloSource, $ffHello.Length) -ForegroundColor DarkCyan
		if ($ffHello.Length -lt 1200) {
			Write-Host "NOTE: Firefox hello is small (no PQ). For Chrome-class DPI use firefox_hello_from_pcap.bin (~1.9KB)." -ForegroundColor DarkYellow
		}
	} else {
		Write-Host ("FirefoxHelloFile missing ({0}) - Compare continues without FF leg." -f $FirefoxHelloFile) -ForegroundColor Yellow
	}

	Write-Host "Capturing RFC ClientHello via SslStream (Schannel)..."
	$sslHello = [DpiHelloEmuV7]::CaptureSslStreamClientHello($Sni, 5000)
	$sslOut = Join-Path (Get-Location) 'tools\Dumps\sslstream_hello.bin'
	try {
		$dir = Split-Path -Parent $sslOut
		if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
		[IO.File]::WriteAllBytes($sslOut, $sslHello)
		Write-Host ("Saved SslStream Hello: {0} ({1} B)" -f $sslOut, $sslHello.Length)
	} catch {
		Write-Host ("SslStream Hello capture ok ({0} B), save skipped: {1}" -f $sslHello.Length, $_.Exception.Message)
	}
} else {
	if ($Mode -eq 'Bucket' -and -not $TGHelloFile) {
		throw "Mode Bucket requires -TGHelloFile (use TG or Chrome-class Hello that DPI drops)."
	}
	$helloBytes = Resolve-HelloBytes
}

if ($Mode -eq 'Compare') {
	Write-Host "DPI ClientHello COMPARE (fingerprint theory)"
	Write-Host ("Target={0}:{1}  Sni={2}" -f $Ip, $Port, $Sni)
	Write-Host ("TG hello:     tg:{0} ({1} B)" -f $TGHelloFile, $tgHello.Length)
	Write-Host ("Chrome hello: {0} ({1} B)" -f $chromeHelloSource, $chromeHello.Length)
	if ($ffHello) {
		Write-Host ("FF hello:     {0} ({1} B)" -f $ffHelloSource, $ffHello.Length)
	}
	Write-Host ("SSL hello:    sslstream ({0} B)" -f $sslHello.Length)
	Write-Host "Key metric for DPI fingerprint: NoReply rate (not ServerHello)."
} elseif ($Mode -eq 'Bucket') {
	Write-Host "DPI precise bucket probe (C(delta) / pure-idle recovery / sustain)"
	Write-Host ("Target={0}:{1}  TGHelloFile={2} ({3} B)" -f $Ip, $Port, $TGHelloFile, $helloBytes.Length)
	Write-Host "Success = ServerHello. Cold gate before each test."
} else {
	$script:helloSource = if ($TGHelloFile) { "TGHelloFile:$TGHelloFile ($($helloBytes.Length) B)" } else { "crafted ($($helloBytes.Length) B)" }
	$helloSni = [DpiHelloEmuV7]::GetClientHelloSni($helloBytes)
	Write-Host "DPI ClientHello emulator"
	Write-Host ("Mode={0}  Target={1}:{2}  Hello={3}  SniParam={4}  HelloSNI={5}" -f `
		$Mode, $Ip, $Port, $script:helloSource, $Sni, $helloSni)
}
Write-Host "Close Telegram during the test. Use a fresh PowerShell if Add-Type was loaded earlier."

$all = New-Object System.Collections.Generic.List[object]

if ($Mode -eq 'Burst') {
	for ($r = 1; $r -le $Rounds; $r++) {
		Write-Host ""
		Write-Host ("=== BURST round {0}/{1} : {2} simultaneous ClientHello -> {3}:{4} ===" -f `
			$r, $Rounds, $BurstCount, $Ip, $Port) -ForegroundColor Cyan
		$sw = [System.Diagnostics.Stopwatch]::StartNew()
		$attempts = [DpiHelloEmuV7]::RunBurst($Ip, $Port, $BurstCount, $helloBytes, $ConnectTimeoutMs, $WaitMs)
		$wall = [int]$sw.ElapsedMilliseconds
		$stats = Get-AttemptStats $attempts
		$rows = Convert-AttemptsToRows -Attempts $attempts -Round $r -WallMs $wall -PaceMs 0 -Phase 'burst'
		foreach ($row in $rows) { $all.Add($row) | Out-Null }
		Write-AttemptStats $stats $wall $BurstCount
		if ($r -lt $Rounds) {
			Write-Host ("Pause {0} ms..." -f $RoundDelayMs) -ForegroundColor DarkYellow
			Start-Sleep -Milliseconds $RoundDelayMs
		}
	}
}
elseif ($Mode -eq 'Paced') {
	for ($r = 1; $r -le $Rounds; $r++) {
		Write-Host ""
		Write-Host ("=== PACED round {0}/{1} : {2} Hellos, gap={3}ms -> {4}:{5} ===" -f `
			$r, $Rounds, $BurstCount, $PaceMs, $Ip, $Port) -ForegroundColor Cyan
		$sw = [System.Diagnostics.Stopwatch]::StartNew()
		$attempts = [DpiHelloEmuV7]::RunPaced($Ip, $Port, $BurstCount, $helloBytes, $ConnectTimeoutMs, $WaitMs, $PaceMs)
		$wall = [int]$sw.ElapsedMilliseconds
		$stats = Get-AttemptStats $attempts
		$rows = Convert-AttemptsToRows -Attempts $attempts -Round $r -WallMs $wall -PaceMs $PaceMs -Phase 'paced'
		foreach ($row in $rows) { $all.Add($row) | Out-Null }
		Write-AttemptStats $stats $wall $BurstCount
		if ($r -lt $Rounds) {
			Write-Host ("Pause {0} ms..." -f $RoundDelayMs) -ForegroundColor DarkYellow
			Start-Sleep -Milliseconds $RoundDelayMs
		}
	}
}
elseif ($Mode -eq 'Sweep') {
	if ($SweepStepMs -le 0) { throw "SweepStepMs must be > 0" }
	Write-Host ""
	Write-Host ("=== SWEEP pace {0}ms -> {1}ms step -{2}ms, {3} trials/level, passRate>={4} ===" -f `
		$SweepStartMs, $SweepMinMs, $SweepStepMs, $TrialsPerDelay, $PassRate) -ForegroundColor Magenta
	$minOkPace = $null
	$firstFailPace = $null
	$pace = $SweepStartMs
	$level = 0
	while ($pace -ge $SweepMinMs) {
		$level++
		Write-Host ""
		Write-Host ("--- level {0}: PaceMs={1}  trials={2} ---" -f $level, $pace, $TrialsPerDelay) -ForegroundColor Cyan
		$sw = [System.Diagnostics.Stopwatch]::StartNew()
		$attempts = [DpiHelloEmuV7]::RunPaced($Ip, $Port, $TrialsPerDelay, $helloBytes, $ConnectTimeoutMs, $WaitMs, $pace)
		$wall = [int]$sw.ElapsedMilliseconds
		$stats = Get-AttemptStats $attempts
		$rows = Convert-AttemptsToRows -Attempts $attempts -Round $level -WallMs $wall -PaceMs $pace -Phase 'sweep'
		foreach ($row in $rows) { $all.Add($row) | Out-Null }
		Write-AttemptStats $stats $wall $TrialsPerDelay
		$passed = ($stats.HelloSent -gt 0) -and ($stats.ServerHelloRate + 1e-9 -ge $PassRate)
		if ($passed) {
			$minOkPace = $pace
			Write-Host ("PASS at {0}ms (ServerHello {1}/{2})" -f $pace, $stats.ServerHello, $stats.HelloSent) -ForegroundColor Green
		} else {
			$firstFailPace = $pace
			$needPct = [int][math]::Round(100.0 * $PassRate)
			Write-Host ("FAIL at {0}ms (ServerHello {1}/{2}, need >={3}%)" -f `
				$pace, $stats.ServerHello, $stats.HelloSent, $needPct) -ForegroundColor Red
			break
		}
		if ($pace -eq $SweepMinMs) { break }
		$next = $pace - $SweepStepMs
		if ($next -lt $SweepMinMs) { $next = $SweepMinMs }
		if ($next -eq $pace) { break }
		Write-Host ("Cooldown {0} ms before next level..." -f $RoundDelayMs) -ForegroundColor DarkYellow
		Start-Sleep -Milliseconds $RoundDelayMs
		$pace = $next
	}
	Write-Host ""
	Write-Host "=== SWEEP RESULT ===" -ForegroundColor Magenta
	if ($null -ne $minOkPace -and $null -eq $firstFailPace) {
		Write-Host ("All tested paces passed. Min tested OK pace = {0}ms." -f $minOkPace)
	} elseif ($null -ne $minOkPace -and $null -ne $firstFailPace) {
		Write-Host ("Minimal OK pace ~= {0}ms. First FAIL = {1}ms." -f $minOkPace, $firstFailPace) -ForegroundColor Green
	} elseif ($null -eq $minOkPace) {
		Write-Host ("Even SweepStartMs={0} failed." -f $SweepStartMs) -ForegroundColor Red
	}
}
elseif ($Mode -eq 'Compare') {
	Write-Host ""
	Write-Host "=== COMPARE: TG vs Chrome vs Firefox vs SslStream ===" -ForegroundColor Magenta
	Write-Host ("Scenarios: BURST x{0}; paced {1}ms x{2}; paced {3}ms x{2}" -f `
		$BurstCount, $CompareSafePaceMs, $TrialsPerDelay, $CompareHotPaceMs)
	Write-Host "Interpretation (primary = TG vs SSL):"
	Write-Host "  FINGERPRINT: TG NoReply high, SSL NoReply low"
	Write-Host "  RATE-ONLY:   TG and SSL both NoReply high"
	Write-Host "  Chrome = ChromeHelloFile; FF = FirefoxHelloFile; SSL = Schannel"

	$tgTag = "tg-pcap:$($tgHello.Length)B"
	$chromeTag = "chrome:$($chromeHello.Length)B"
	$ffTag = if ($ffHello) { "firefox:$($ffHello.Length)B" } else { '' }
	$sslTag = "sslstream:$($sslHello.Length)B"
	$summary = New-Object System.Collections.Generic.List[object]
	$plan = @(
		@{ Name = 'burst'; Burst = $true;  Count = $BurstCount; Pace = 0 },
		@{ Name = "pace-$CompareSafePaceMs"; Burst = $false; Count = $TrialsPerDelay; Pace = $CompareSafePaceMs },
		@{ Name = "pace-$CompareHotPaceMs"; Burst = $false; Count = $TrialsPerDelay; Pace = $CompareHotPaceMs }
	)
	$variants = @(
		@{ Label = 'TG';  Hello = $tgHello;    Tag = $tgTag },
		@{ Label = 'Chrome'; Hello = $chromeHello; Tag = $chromeTag }
	)
	if ($ffHello) {
		$variants += @{ Label = 'FF'; Hello = $ffHello; Tag = $ffTag }
	}
	$variants += @{ Label = 'SSL'; Hello = $sslHello; Tag = $sslTag }
	$firstCompare = $true
	foreach ($sc in $plan) {
		foreach ($var in $variants) {
			if (-not $firstCompare) {
				Write-Host ("Cooldown {0} ms..." -f $RoundDelayMs) -ForegroundColor DarkYellow
				Start-Sleep -Milliseconds $RoundDelayMs
			}
			$firstCompare = $false
			$r = Invoke-HelloScenario -Label $var.Label -Hello $var.Hello -HelloTag $var.Tag `
				-Scenario $sc.Name -Count $sc.Count -PaceMs $sc.Pace -Burst:$sc.Burst
			$summary.Add($r) | Out-Null
		}
	}
	Write-Host ""
	Write-Host "=== COMPARE TABLE (NoReply = DPI-like drop) ===" -ForegroundColor Magenta
	Write-Host ("{0,-16} {1,-8} {2,8} {3,8} {4,10} {5,8} {6}" -f `
		'Scenario', 'Hello', 'Sent', 'SH', 'NoReply%', 'Alert', 'Kinds')
	foreach ($r in $summary) {
		$kinds = ($r.Stats.Kinds.GetEnumerator() | Sort-Object Name | ForEach-Object { "{0}={1}" -f $_.Key, $_.Value }) -join ','
		$nrPct = [int][math]::Round(100.0 * $r.Stats.NoReplyRate)
		Write-Host ("{0,-16} {1,-8} {2,8} {3,8} {4,9}% {5,8} {6}" -f `
			$r.Scenario, $r.Label, $r.Stats.HelloSent, $r.Stats.ServerHello, `
			$nrPct, $r.Stats.Alert, $kinds)
	}
	Write-Host ""
	Write-Host "=== COMPARE VERDICT (TG vs SSL; Chrome/FF controls) ===" -ForegroundColor Magenta
	foreach ($name in ($plan | ForEach-Object { $_.Name })) {
		$tg = $summary | Where-Object { $_.Scenario -eq $name -and $_.Label -eq 'TG' } | Select-Object -First 1
		$ssl = $summary | Where-Object { $_.Scenario -eq $name -and $_.Label -eq 'SSL' } | Select-Object -First 1
		$ch = $summary | Where-Object { $_.Scenario -eq $name -and $_.Label -eq 'Chrome' } | Select-Object -First 1
		$ff = $summary | Where-Object { $_.Scenario -eq $name -and $_.Label -eq 'FF' } | Select-Object -First 1
		if (-not $tg -or -not $ssl) { continue }
		$tgNr = $tg.Stats.NoReplyRate
		$sslNr = $ssl.Stats.NoReplyRate
		$chNr = if ($ch) { $ch.Stats.NoReplyRate } else { -1 }
		$ffNr = if ($ff) { $ff.Stats.NoReplyRate } else { -1 }
		if ($tgNr -ge 0.5 -and $sslNr -lt 0.25) {
			$v = "FINGERPRINT: TG dropped, SslStream answered"
		} elseif ($tgNr -ge 0.5 -and $sslNr -ge 0.5) {
			$v = "RATE-ONLY: TG and SslStream both dropped"
		} elseif ($tgNr -lt 0.25 -and $sslNr -lt 0.25) {
			$v = "NO DROP: TG and SslStream both answered"
		} else {
			$v = ("MIXED: TG NoReply={0}% SSL NoReply={1}%" -f `
				([int][math]::Round(100.0 * $tgNr)),
				([int][math]::Round(100.0 * $sslNr)))
		}
		if ($chNr -ge 0) {
			$v = $v + (" | Chrome NoReply={0}%" -f ([int][math]::Round(100.0 * $chNr)))
		}
		if ($ffNr -ge 0) {
			$v = $v + (" | FF NoReply={0}%" -f ([int][math]::Round(100.0 * $ffNr)))
		}
		Write-Host ("{0}: {1}" -f $name, $v)
	}
}
elseif ($Mode -eq 'Bucket') {
	$script:helloSource = "TGHelloFile:$TGHelloFile ($($helloBytes.Length) B)"
	Write-Host ""
	Write-Host "=== PRECISE BUCKET: C(delta) + pure-idle recovery + sustain ===" -ForegroundColor Magenta
	Write-Host "Rules: cold gate before each test; no probes during pure-idle recovery (default)."
	Write-Host ("cooldown={0}ms  capacityPaces={1}  rounds/pace={2}" -f $RoundDelayMs, $BucketCapacityPacesMs, $BucketCapacityRounds)

	function Parse-IntList([string] $s) {
		$out = @()
		foreach ($x in ($s -split ',')) {
			$x = $x.Trim()
			if ($x -ne '') { $out += [int]$x }
		}
		return $out
	}

	$capPaceList = Parse-IntList $BucketCapacityPacesMs
	if ($capPaceList.Count -eq 0) { $capPaceList = @($BucketFillPaceMs) }

	$capByPace = @{}
	foreach ($fillPace in $capPaceList) {
		Write-Host ""
		Write-Host ("=== CAPACITY curve at fillPace={0}ms ===" -f $fillPace) -ForegroundColor Magenta
		$samples = New-Object System.Collections.Generic.List[int]
		for ($r = 1; $r -le $BucketCapacityRounds; $r++) {
			Wait-DpiCold -Hello $helloBytes -Phase ("bucket-cold-cap-{0}-{1}" -f $fillPace, $r)
			Write-Host ("--- capacity pace={0} round {1}/{2} ---" -f $fillPace, $r, $BucketCapacityRounds) -ForegroundColor Cyan
			$streak = Measure-DpiCapacityStreak -Hello $helloBytes -FillPaceMs $fillPace -Round $r -Phase ("bucket-cap-{0}" -f $fillPace)
			$samples.Add($streak) | Out-Null
		}
		$med = Get-MedianInt -Values $samples.ToArray()
		$capByPace[$fillPace] = [pscustomobject]@{ PaceMs = $fillPace; Samples = ($samples -join ','); Median = $med }
		Write-Host ("CAPACITY@{0}ms samples={1} median={2}" -f $fillPace, ($samples -join ','), $med) -ForegroundColor Yellow
	}

	Write-Host ""
	Write-Host "=== CAPACITY vs FILL-PACE ===" -ForegroundColor Magenta
	Write-Host ("{0,10} {1,12} {2}" -f 'FillPace', 'Median C', 'Samples')
	foreach ($fillPace in ($capByPace.Keys | Sort-Object)) {
		$row = $capByPace[$fillPace]
		Write-Host ("{0,10} {1,12} {2}" -f $row.PaceMs, $row.Median, $row.Samples)
	}

	$capMedFast = 0
	if ($capByPace.ContainsKey(50)) { $capMedFast = $capByPace[50].Median }
	elseif ($capByPace.ContainsKey($BucketFillPaceMs)) { $capMedFast = $capByPace[$BucketFillPaceMs].Median }
	else {
		$first = ($capByPace.Keys | Sort-Object | Select-Object -First 1)
		$capMedFast = $capByPace[$first].Median
	}

	Write-Host ""
	Write-Host "=== RECOVERY ===" -ForegroundColor Magenta
	Wait-DpiCold -Hello $helloBytes -Phase 'bucket-cold-recover'
	$fillN = [math]::Max($capMedFast + 5, 10)
	$fillPace = $BucketFillPaceMs
	Write-Host ("Trip bucket: {0} Hellos at {1}ms..." -f $fillN, $fillPace)
	[void][DpiHelloEmuV7]::RunPaced($Ip, $Port, $fillN, $helloBytes, $ConnectTimeoutMs, $WaitMs, $fillPace)

	$recoveredAt = $null
	if ($BucketProbeDuringRecover) {
		Write-Host "Recover mode: probe every step (may EXTEND block)"
		$waited = 0
		while ($waited -le $BucketRecoverMaxMs) {
			Start-Sleep -Milliseconds $BucketRecoverStepMs
			$waited += $BucketRecoverStepMs
			$attempts = [DpiHelloEmuV7]::RunPaced($Ip, $Port, 1, $helloBytes, $ConnectTimeoutMs, $WaitMs, 0)
			$a = $attempts[0]
			$rows = Convert-AttemptsToRows -Attempts $attempts -Round 0 -WallMs 0 -PaceMs $waited -Phase 'bucket-recover-probe'
			foreach ($row in $rows) { $all.Add($row) | Out-Null }
			if ($a.GotServerHello) {
				$recoveredAt = $waited
				Write-Host ("  RECOVERED (probe-during) after ~{0}ms" -f $waited) -ForegroundColor Green
				break
			}
			Write-Host ("  blocked at {0}ms" -f $waited) -ForegroundColor DarkYellow
		}
	} else {
		Write-Host "Recover mode: PURE idle (re-trip before each wait candidate, no packets during wait)"
		$lo = 0
		$best = $null
		$points = New-Object System.Collections.Generic.List[int]
		$t = $BucketRecoverStepMs
		while ($t -le $BucketRecoverMaxMs) {
			$points.Add($t) | Out-Null
			$t = [int]([math]::Max($t * 2, $t + $BucketRecoverStepMs))
		}
		if (-not $points.Contains($BucketRecoverMaxMs)) { $points.Add($BucketRecoverMaxMs) | Out-Null }
		foreach ($waitCand in $points) {
			Write-Host ("  pure idle {0}ms then 1 probe..." -f $waitCand) -ForegroundColor Cyan
			[void][DpiHelloEmuV7]::RunPaced($Ip, $Port, $fillN, $helloBytes, $ConnectTimeoutMs, $WaitMs, $fillPace)
			Start-Sleep -Milliseconds $waitCand
			$attempts = [DpiHelloEmuV7]::RunPaced($Ip, $Port, 1, $helloBytes, $ConnectTimeoutMs, $WaitMs, 0)
			$a = $attempts[0]
			$rows = Convert-AttemptsToRows -Attempts $attempts -Round 0 -WallMs 0 -PaceMs $waitCand -Phase 'bucket-recover-pure'
			foreach ($row in $rows) { $all.Add($row) | Out-Null }
			if ($a.GotServerHello) {
				Write-Host ("  SH after pure idle {0}ms" -f $waitCand) -ForegroundColor Green
				$best = $waitCand
				break
			} else {
				Write-Host ("  still blocked after pure idle {0}ms" -f $waitCand) -ForegroundColor Red
				$lo = $waitCand
			}
		}
		if (($null -ne $best) -and ($best -gt $BucketRecoverStepMs)) {
			$left = $lo
			$right = $best
			while (($right - $left) -gt $BucketRecoverStepMs) {
				$mid = [int](($left + $right) / 2)
				$mid = [int]([math]::Ceiling($mid / [double]$BucketRecoverStepMs) * $BucketRecoverStepMs)
				if ($mid -le $left) { $mid = $left + $BucketRecoverStepMs }
				if ($mid -ge $right) { break }
				Write-Host ("  refine: pure idle {0}ms..." -f $mid) -ForegroundColor Cyan
				[void][DpiHelloEmuV7]::RunPaced($Ip, $Port, $fillN, $helloBytes, $ConnectTimeoutMs, $WaitMs, $fillPace)
				Start-Sleep -Milliseconds $mid
				$attempts = [DpiHelloEmuV7]::RunPaced($Ip, $Port, 1, $helloBytes, $ConnectTimeoutMs, $WaitMs, 0)
				$a = $attempts[0]
				$rows = Convert-AttemptsToRows -Attempts $attempts -Round 0 -WallMs 0 -PaceMs $mid -Phase 'bucket-recover-refine'
				foreach ($row in $rows) { $all.Add($row) | Out-Null }
				if ($a.GotServerHello) {
					Write-Host ("  SH @ {0}ms" -f $mid) -ForegroundColor Green
					$right = $mid
					$best = $mid
				} else {
					Write-Host ("  block @ {0}ms" -f $mid) -ForegroundColor Red
					$left = $mid
				}
			}
		}
		$recoveredAt = $best
		if ($null -eq $recoveredAt) {
			Write-Host ("  No recovery within {0}ms pure idle" -f $BucketRecoverMaxMs) -ForegroundColor Red
		} else {
			Write-Host ("  PURE-IDLE recovery ~= {0}ms" -f $recoveredAt) -ForegroundColor Green
		}
	}

	Write-Host ""
	Write-Host "=== SUSTAIN ===" -ForegroundColor Magenta
	$paceList = Parse-IntList $BucketSustainPacesMs
	$sustainOk = $null
	$sustainFail = $null
	if ($BucketSustainBinary -and $paceList.Count -ge 2) {
		$hiPace = ($paceList | Measure-Object -Maximum).Maximum
		$loPace = ($paceList | Measure-Object -Minimum).Minimum
		Write-Host ("Binary sustain search between {0}ms and {1}ms (step~25ms)" -f $loPace, $hiPace)
		$left = $loPace
		$right = $hiPace
		$bestPass = $null
		while (($right - $left) -gt 25) {
			$mid = [int](($left + $right) / 2)
			$mid = [int]([math]::Round($mid / 25.0) * 25)
			if ($mid -le $left) { $mid = $left + 25 }
			if ($mid -ge $right) { break }
			Wait-DpiCold -Hello $helloBytes -Phase ("bucket-cold-sus-{0}" -f $mid)
			Write-Host ("--- sustain binary pace={0}ms count={1} ---" -f $mid, $BucketSustainCount) -ForegroundColor Cyan
			$sw = [System.Diagnostics.Stopwatch]::StartNew()
			$attempts = [DpiHelloEmuV7]::RunPaced($Ip, $Port, $BucketSustainCount, $helloBytes, $ConnectTimeoutMs, $WaitMs, $mid)
			$wall = [int]$sw.ElapsedMilliseconds
			$stats = Get-AttemptStats $attempts
			$rows = Convert-AttemptsToRows -Attempts $attempts -Round 0 -WallMs $wall -PaceMs $mid -Phase 'bucket-sustain-bin'
			foreach ($row in $rows) { $all.Add($row) | Out-Null }
			Write-AttemptStats $stats $wall $BucketSustainCount
			$passed = ($stats.HelloSent -gt 0) -and ($stats.ServerHelloRate + 1e-9 -ge $PassRate)
			if ($passed) {
				$bestPass = $mid
				$right = $mid
				Write-Host ("PASS {0}ms -> search lower" -f $mid) -ForegroundColor Green
			} else {
				$left = $mid
				$sustainFail = $mid
				Write-Host ("FAIL {0}ms -> search higher" -f $mid) -ForegroundColor Red
			}
		}
		$sustainOk = $bestPass
	} else {
		foreach ($pace in ($paceList | Sort-Object -Descending)) {
			Wait-DpiCold -Hello $helloBytes -Phase ("bucket-cold-sus-{0}" -f $pace)
			Write-Host ("--- sustain pace={0}ms count={1} ---" -f $pace, $BucketSustainCount) -ForegroundColor Cyan
			$sw = [System.Diagnostics.Stopwatch]::StartNew()
			$attempts = [DpiHelloEmuV7]::RunPaced($Ip, $Port, $BucketSustainCount, $helloBytes, $ConnectTimeoutMs, $WaitMs, $pace)
			$wall = [int]$sw.ElapsedMilliseconds
			$stats = Get-AttemptStats $attempts
			$rows = Convert-AttemptsToRows -Attempts $attempts -Round 0 -WallMs $wall -PaceMs $pace -Phase 'bucket-sustain'
			foreach ($row in $rows) { $all.Add($row) | Out-Null }
			Write-AttemptStats $stats $wall $BucketSustainCount
			$passed = ($stats.HelloSent -gt 0) -and ($stats.ServerHelloRate + 1e-9 -ge $PassRate)
			if ($passed) {
				$sustainOk = $pace
				Write-Host ("PASS sustain at {0}ms" -f $pace) -ForegroundColor Green
			} else {
				$sustainFail = $pace
				Write-Host ("FAIL sustain at {0}ms" -f $pace) -ForegroundColor Red
			}
		}
	}

	Write-Host ""
	Write-Host "=== BUCKET MODEL (precise) ===" -ForegroundColor Magenta
	Write-Host "C depends on inter-arrival: see CAPACITY vs FILL-PACE (not a single N)."
	foreach ($fillPace in ($capByPace.Keys | Sort-Object)) {
		$row = $capByPace[$fillPace]
		Write-Host ("  at delta~{0}ms -> C~={1}" -f $row.PaceMs, $row.Median)
	}
	if ($null -ne $recoveredAt) {
		Write-Host ("Pure-idle recovery after trip T~={0}ms" -f $recoveredAt)
	}
	if ($null -ne $sustainOk) {
		Write-Host ("Min sustained pace (100% SH) P~={0}ms" -f $sustainOk)
	}
	if (($null -ne $sustainFail) -and ($null -ne $sustainOk)) {
		Write-Host ("Sustain cliff between {0}ms (fail) and {1}ms (pass)" -f $sustainFail, $sustainOk)
	}
	$cNearCliff = $null
	if (($null -ne $sustainFail) -and $capByPace.ContainsKey([int]$sustainFail)) {
		$cNearCliff = $capByPace[[int]$sustainFail].Median
	} elseif ($capByPace.ContainsKey(850)) {
		$cNearCliff = $capByPace[850].Median
	}
	if (($null -ne $cNearCliff) -and ($cNearCliff -gt 0) -and ($null -ne $sustainOk)) {
		$win = [math]::Round($cNearCliff * $sustainOk / 1000.0, 1)
		Write-Host ("Sliding-window estimate near cliff: ~{0} Hellos per ~{1}s (C*P)." -f $cNearCliff, $win)
	}
	if (($capMedFast -gt 0) -and ($null -ne $recoveredAt)) {
		Write-Host ("Do NOT read as '{0} per {1}s average rate' - sustain disproves simple full-refill token bucket." -f $capMedFast, [math]::Round($recoveredAt / 1000.0, 1))
	}
	Write-Host "Client guideline: pace >= sustain PASS; avoid bursts > min C(delta)."
}
$helloSent = 0; $reply = 0; $sh = 0; $tcp = 0
$kindTotal = @{}
foreach ($row in $all) {
	if ($row.TcpOk) { $tcp++ }
	if ($row.HelloSent) { $helloSent++ }
	if ($row.GotAnyReply) { $reply++ }
	if ($row.GotServerHello) { $sh++ }
	$k = if ($row.ReplyKind) { $row.ReplyKind } else { 'none' }
	if (-not $kindTotal.ContainsKey($k)) { $kindTotal[$k] = 0 }
	$kindTotal[$k]++
}
Write-Host ""
Write-Host "=== TOTAL ===" -ForegroundColor Magenta
Write-Host ("Attempts={0} TcpOk={1} HelloSent={2} Reply={3} ServerHello={4}" -f `
	$all.Count, $tcp, $helloSent, $reply, $sh)
$kinds = ($kindTotal.GetEnumerator() | Sort-Object Name | ForEach-Object { "{0}={1}" -f $_.Key, $_.Value }) -join ' '
Write-Host ("ReplyKinds: {0}" -f $kinds)
if ($helloSent -gt 0) {
	$shPct = [math]::Round(100.0 * $sh / $helloSent, 1)
	Write-Host ("ServerHello rate: {0}%  (this is the pass metric for TG hello)" -f $shPct)
	$dropPct = [math]::Round(100.0 * ($helloSent - $reply) / $helloSent, 1)
	Write-Host ("Hello with no reply: {0}% (DPI drop signature)" -f $dropPct)
}

if ($CsvOut) {
	$all | Export-Csv -Path $CsvOut -NoTypeInformation -Encoding UTF8
	Write-Host "CSV: $CsvOut"
}
Write-Host "Done."
