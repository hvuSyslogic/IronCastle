﻿using org.bouncycastle.asn1;
using org.bouncycastle.asn1.x509;
using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.nist;

using System;
using System.IO;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.tls
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;
	using KeyUsage = org.bouncycastle.asn1.x509.KeyUsage;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X509ObjectIdentifiers = org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
	using MD5Digest = org.bouncycastle.crypto.digests.MD5Digest;
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using SHA224Digest = org.bouncycastle.crypto.digests.SHA224Digest;
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;
	using SHA384Digest = org.bouncycastle.crypto.digests.SHA384Digest;
	using SHA512Digest = org.bouncycastle.crypto.digests.SHA512Digest;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using DSAPublicKeyParameters = org.bouncycastle.crypto.@params.DSAPublicKeyParameters;
	using ECPublicKeyParameters = org.bouncycastle.crypto.@params.ECPublicKeyParameters;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using RSAKeyParameters = org.bouncycastle.crypto.@params.RSAKeyParameters;
	using PublicKeyFactory = org.bouncycastle.crypto.util.PublicKeyFactory;
	using Arrays = org.bouncycastle.util.Arrays;
	using Integers = org.bouncycastle.util.Integers;
	using Shorts = org.bouncycastle.util.Shorts;
	using Strings = org.bouncycastle.util.Strings;
	using Streams = org.bouncycastle.util.io.Streams;

	/// <summary>
	/// Some helper functions for MicroTLS.
	/// </summary>
	public class TlsUtils
	{
		public static readonly byte[] EMPTY_BYTES = new byte[0];
		public static readonly short[] EMPTY_SHORTS = new short[0];
		public static readonly int[] EMPTY_INTS = new int[0];
		public static readonly long[] EMPTY_LONGS = new long[0];

		public static readonly int? EXT_signature_algorithms = Integers.valueOf(ExtensionType.signature_algorithms);

		public static void checkUint8(short i)
		{
			if (!isValidUint8(i))
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}
		}

		public static void checkUint8(int i)
		{
			if (!isValidUint8(i))
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}
		}

		public static void checkUint8(long i)
		{
			if (!isValidUint8(i))
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}
		}

		public static void checkUint16(int i)
		{
			if (!isValidUint16(i))
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}
		}

		public static void checkUint16(long i)
		{
			if (!isValidUint16(i))
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}
		}

		public static void checkUint24(int i)
		{
			if (!isValidUint24(i))
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}
		}

		public static void checkUint24(long i)
		{
			if (!isValidUint24(i))
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}
		}

		public static void checkUint32(long i)
		{
			if (!isValidUint32(i))
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}
		}

		public static void checkUint48(long i)
		{
			if (!isValidUint48(i))
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}
		}

		public static void checkUint64(long i)
		{
			if (!isValidUint64(i))
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}
		}

		public static bool isValidUint8(short i)
		{
			return (i & 0xFF) == i;
		}

		public static bool isValidUint8(int i)
		{
			return (i & 0xFF) == i;
		}

		public static bool isValidUint8(long i)
		{
			return (i & 0xFFL) == i;
		}

		public static bool isValidUint16(int i)
		{
			return (i & 0xFFFF) == i;
		}

		public static bool isValidUint16(long i)
		{
			return (i & 0xFFFFL) == i;
		}

		public static bool isValidUint24(int i)
		{
			return (i & 0xFFFFFF) == i;
		}

		public static bool isValidUint24(long i)
		{
			return (i & 0xFFFFFFL) == i;
		}

		public static bool isValidUint32(long i)
		{
			return (i & 0xFFFFFFFFL) == i;
		}

		public static bool isValidUint48(long i)
		{
			return (i & 0xFFFFFFFFFFFFL) == i;
		}

		public static bool isValidUint64(long i)
		{
			return true;
		}

		public static bool isSSL(TlsContext context)
		{
			return context.getServerVersion().isSSL();
		}

		public static bool isTLSv11(ProtocolVersion version)
		{
			return ProtocolVersion.TLSv11.isEqualOrEarlierVersionOf(version.getEquivalentTLSVersion());
		}

		public static bool isTLSv11(TlsContext context)
		{
			return isTLSv11(context.getServerVersion());
		}

		public static bool isTLSv12(ProtocolVersion version)
		{
			return ProtocolVersion.TLSv12.isEqualOrEarlierVersionOf(version.getEquivalentTLSVersion());
		}

		public static bool isTLSv12(TlsContext context)
		{
			return isTLSv12(context.getServerVersion());
		}

		public static void writeUint8(short i, OutputStream output)
		{
			output.write(i);
		}

		public static void writeUint8(int i, OutputStream output)
		{
			output.write(i);
		}

		public static void writeUint8(short i, byte[] buf, int offset)
		{
			buf[offset] = (byte)i;
		}

		public static void writeUint8(int i, byte[] buf, int offset)
		{
			buf[offset] = (byte)i;
		}

		public static void writeUint16(int i, OutputStream output)
		{
			output.write((int)((uint)i >> 8));
			output.write(i);
		}

		public static void writeUint16(int i, byte[] buf, int offset)
		{
			buf[offset] = (byte)((int)((uint)i >> 8));
			buf[offset + 1] = (byte)i;
		}

		public static void writeUint24(int i, OutputStream output)
		{
			output.write((byte)((int)((uint)i >> 16)));
			output.write((byte)((int)((uint)i >> 8)));
			output.write((byte)i);
		}

		public static void writeUint24(int i, byte[] buf, int offset)
		{
			buf[offset] = (byte)((int)((uint)i >> 16));
			buf[offset + 1] = (byte)((int)((uint)i >> 8));
			buf[offset + 2] = (byte)i;
		}

		public static void writeUint32(long i, OutputStream output)
		{
			output.write((byte)((long)((ulong)i >> 24)));
			output.write((byte)((long)((ulong)i >> 16)));
			output.write((byte)((long)((ulong)i >> 8)));
			output.write((byte)i);
		}

		public static void writeUint32(long i, byte[] buf, int offset)
		{
			buf[offset] = (byte)((long)((ulong)i >> 24));
			buf[offset + 1] = (byte)((long)((ulong)i >> 16));
			buf[offset + 2] = (byte)((long)((ulong)i >> 8));
			buf[offset + 3] = (byte)i;
		}

		public static void writeUint48(long i, OutputStream output)
		{
			output.write((byte)((long)((ulong)i >> 40)));
			output.write((byte)((long)((ulong)i >> 32)));
			output.write((byte)((long)((ulong)i >> 24)));
			output.write((byte)((long)((ulong)i >> 16)));
			output.write((byte)((long)((ulong)i >> 8)));
			output.write((byte)i);
		}

		public static void writeUint48(long i, byte[] buf, int offset)
		{
			buf[offset] = (byte)((long)((ulong)i >> 40));
			buf[offset + 1] = (byte)((long)((ulong)i >> 32));
			buf[offset + 2] = (byte)((long)((ulong)i >> 24));
			buf[offset + 3] = (byte)((long)((ulong)i >> 16));
			buf[offset + 4] = (byte)((long)((ulong)i >> 8));
			buf[offset + 5] = (byte)i;
		}

		public static void writeUint64(long i, OutputStream output)
		{
			output.write((byte)((long)((ulong)i >> 56)));
			output.write((byte)((long)((ulong)i >> 48)));
			output.write((byte)((long)((ulong)i >> 40)));
			output.write((byte)((long)((ulong)i >> 32)));
			output.write((byte)((long)((ulong)i >> 24)));
			output.write((byte)((long)((ulong)i >> 16)));
			output.write((byte)((long)((ulong)i >> 8)));
			output.write((byte)i);
		}

		public static void writeUint64(long i, byte[] buf, int offset)
		{
			buf[offset] = (byte)((long)((ulong)i >> 56));
			buf[offset + 1] = (byte)((long)((ulong)i >> 48));
			buf[offset + 2] = (byte)((long)((ulong)i >> 40));
			buf[offset + 3] = (byte)((long)((ulong)i >> 32));
			buf[offset + 4] = (byte)((long)((ulong)i >> 24));
			buf[offset + 5] = (byte)((long)((ulong)i >> 16));
			buf[offset + 6] = (byte)((long)((ulong)i >> 8));
			buf[offset + 7] = (byte)i;
		}

		public static void writeOpaque8(byte[] buf, OutputStream output)
		{
			checkUint8(buf.Length);
			writeUint8(buf.Length, output);
			output.write(buf);
		}

		public static void writeOpaque16(byte[] buf, OutputStream output)
		{
			checkUint16(buf.Length);
			writeUint16(buf.Length, output);
			output.write(buf);
		}

		public static void writeOpaque24(byte[] buf, OutputStream output)
		{
			checkUint24(buf.Length);
			writeUint24(buf.Length, output);
			output.write(buf);
		}

		public static void writeUint8Array(short[] uints, OutputStream output)
		{
			for (int i = 0; i < uints.Length; ++i)
			{
				writeUint8(uints[i], output);
			}
		}

		public static void writeUint8Array(short[] uints, byte[] buf, int offset)
		{
			for (int i = 0; i < uints.Length; ++i)
			{
				writeUint8(uints[i], buf, offset);
				++offset;
			}
		}

		public static void writeUint8ArrayWithUint8Length(short[] uints, OutputStream output)
		{
			checkUint8(uints.Length);
			writeUint8(uints.Length, output);
			writeUint8Array(uints, output);
		}

		public static void writeUint8ArrayWithUint8Length(short[] uints, byte[] buf, int offset)
		{
			checkUint8(uints.Length);
			writeUint8(uints.Length, buf, offset);
			writeUint8Array(uints, buf, offset + 1);
		}

		public static void writeUint16Array(int[] uints, OutputStream output)
		{
			for (int i = 0; i < uints.Length; ++i)
			{
				writeUint16(uints[i], output);
			}
		}

		public static void writeUint16Array(int[] uints, byte[] buf, int offset)
		{
			for (int i = 0; i < uints.Length; ++i)
			{
				writeUint16(uints[i], buf, offset);
				offset += 2;
			}
		}

		public static void writeUint16ArrayWithUint16Length(int[] uints, OutputStream output)
		{
			int length = 2 * uints.Length;
			checkUint16(length);
			writeUint16(length, output);
			writeUint16Array(uints, output);
		}

		public static void writeUint16ArrayWithUint16Length(int[] uints, byte[] buf, int offset)
		{
			int length = 2 * uints.Length;
			checkUint16(length);
			writeUint16(length, buf, offset);
			writeUint16Array(uints, buf, offset + 2);
		}

		public static byte[] encodeOpaque8(byte[] buf)
		{
			checkUint8(buf.Length);
			return Arrays.prepend(buf, (byte)buf.Length);
		}

		public static byte[] encodeUint8ArrayWithUint8Length(short[] uints)
		{
			byte[] result = new byte[1 + uints.Length];
			writeUint8ArrayWithUint8Length(uints, result, 0);
			return result;
		}

		public static byte[] encodeUint16ArrayWithUint16Length(int[] uints)
		{
			int length = 2 * uints.Length;
			byte[] result = new byte[2 + length];
			writeUint16ArrayWithUint16Length(uints, result, 0);
			return result;
		}

		public static short readUint8(InputStream input)
		{
			int i = input.read();
			if (i < 0)
			{
				throw new EOFException();
			}
			return (short)i;
		}

		public static short readUint8(byte[] buf, int offset)
		{
			return (short)(buf[offset] & 0xff);
		}

		public static int readUint16(InputStream input)
		{
			int i1 = input.read();
			int i2 = input.read();
			if (i2 < 0)
			{
				throw new EOFException();
			}
			return (i1 << 8) | i2;
		}

		public static int readUint16(byte[] buf, int offset)
		{
			int n = (buf[offset] & 0xff) << 8;
			n |= (buf[++offset] & 0xff);
			return n;
		}

		public static int readUint24(InputStream input)
		{
			int i1 = input.read();
			int i2 = input.read();
			int i3 = input.read();
			if (i3 < 0)
			{
				throw new EOFException();
			}
			return (i1 << 16) | (i2 << 8) | i3;
		}

		public static int readUint24(byte[] buf, int offset)
		{
			int n = (buf[offset] & 0xff) << 16;
			n |= (buf[++offset] & 0xff) << 8;
			n |= (buf[++offset] & 0xff);
			return n;
		}

		public static long readUint32(InputStream input)
		{
			int i1 = input.read();
			int i2 = input.read();
			int i3 = input.read();
			int i4 = input.read();
			if (i4 < 0)
			{
				throw new EOFException();
			}
			return ((i1 << 24) | (i2 << 16) | (i3 << 8) | i4) & 0xFFFFFFFFL;
		}

		public static long readUint32(byte[] buf, int offset)
		{
			int n = (buf[offset] & 0xff) << 24;
			n |= (buf[++offset] & 0xff) << 16;
			n |= (buf[++offset] & 0xff) << 8;
			n |= (buf[++offset] & 0xff);
			return n & 0xFFFFFFFFL;
		}

		public static long readUint48(InputStream input)
		{
			int hi = readUint24(input);
			int lo = readUint24(input);
			return ((long)(hi & 0xffffffffL) << 24) | (long)(lo & 0xffffffffL);
		}

		public static long readUint48(byte[] buf, int offset)
		{
			int hi = readUint24(buf, offset);
			int lo = readUint24(buf, offset + 3);
			return ((long)(hi & 0xffffffffL) << 24) | (long)(lo & 0xffffffffL);
		}

		public static byte[] readAllOrNothing(int length, InputStream input)
		{
			if (length < 1)
			{
				return EMPTY_BYTES;
			}
			byte[] buf = new byte[length];
			int read = Streams.readFully(input, buf);
			if (read == 0)
			{
				return null;
			}
			if (read != length)
			{
				throw new EOFException();
			}
			return buf;
		}

		public static byte[] readFully(int length, InputStream input)
		{
			if (length < 1)
			{
				return EMPTY_BYTES;
			}
			byte[] buf = new byte[length];
			if (length != Streams.readFully(input, buf))
			{
				throw new EOFException();
			}
			return buf;
		}

		public static void readFully(byte[] buf, InputStream input)
		{
			int length = buf.Length;
			if (length > 0 && length != Streams.readFully(input, buf))
			{
				throw new EOFException();
			}
		}

		public static byte[] readOpaque8(InputStream input)
		{
			short length = readUint8(input);
			return readFully(length, input);
		}

		public static byte[] readOpaque16(InputStream input)
		{
			int length = readUint16(input);
			return readFully(length, input);
		}

		public static byte[] readOpaque24(InputStream input)
		{
			int length = readUint24(input);
			return readFully(length, input);
		}

		public static short[] readUint8Array(int count, InputStream input)
		{
			short[] uints = new short[count];
			for (int i = 0; i < count; ++i)
			{
				uints[i] = readUint8(input);
			}
			return uints;
		}

		public static int[] readUint16Array(int count, InputStream input)
		{
			int[] uints = new int[count];
			for (int i = 0; i < count; ++i)
			{
				uints[i] = readUint16(input);
			}
			return uints;
		}

		public static ProtocolVersion readVersion(byte[] buf, int offset)
		{
			return ProtocolVersion.get(buf[offset] & 0xFF, buf[offset + 1] & 0xFF);
		}

		public static ProtocolVersion readVersion(InputStream input)
		{
			int i1 = input.read();
			int i2 = input.read();
			if (i2 < 0)
			{
				throw new EOFException();
			}
			return ProtocolVersion.get(i1, i2);
		}

		public static int readVersionRaw(byte[] buf, int offset)
		{
			return (buf[offset] << 8) | buf[offset + 1];
		}

		public static int readVersionRaw(InputStream input)
		{
			int i1 = input.read();
			int i2 = input.read();
			if (i2 < 0)
			{
				throw new EOFException();
			}
			return (i1 << 8) | i2;
		}

		public static ASN1Primitive readASN1Object(byte[] encoding)
		{
			ASN1InputStream asn1 = new ASN1InputStream(encoding);
			ASN1Primitive result = asn1.readObject();
			if (null == result)
			{
				throw new TlsFatalAlert(AlertDescription.decode_error);
			}
			if (null != asn1.readObject())
			{
				throw new TlsFatalAlert(AlertDescription.decode_error);
			}
			return result;
		}

		public static ASN1Primitive readDERObject(byte[] encoding)
		{
			/*
			 * NOTE: The current ASN.1 parsing code can't enforce DER-only parsing, but since DER is
			 * canonical, we can check it by re-encoding the result and comparing to the original.
			 */
			ASN1Primitive result = readASN1Object(encoding);
			byte[] check = result.getEncoded(ASN1Encoding_Fields.DER);
			if (!Arrays.areEqual(check, encoding))
			{
				throw new TlsFatalAlert(AlertDescription.decode_error);
			}
			return result;
		}

		public static void writeGMTUnixTime(byte[] buf, int offset)
		{
			int t = (int)(JavaSystem.currentTimeMillis() / 1000L);
			buf[offset] = (byte)((int)((uint)t >> 24));
			buf[offset + 1] = (byte)((int)((uint)t >> 16));
			buf[offset + 2] = (byte)((int)((uint)t >> 8));
			buf[offset + 3] = (byte)t;
		}

		public static void writeVersion(ProtocolVersion version, OutputStream output)
		{
			output.write(version.getMajorVersion());
			output.write(version.getMinorVersion());
		}

		public static void writeVersion(ProtocolVersion version, byte[] buf, int offset)
		{
			buf[offset] = (byte)version.getMajorVersion();
			buf[offset + 1] = (byte)version.getMinorVersion();
		}

		public static Vector getAllSignatureAlgorithms()
		{
			Vector v = new Vector(4);
			v.addElement(Shorts.valueOf(SignatureAlgorithm.anonymous));
			v.addElement(Shorts.valueOf(SignatureAlgorithm.rsa));
			v.addElement(Shorts.valueOf(SignatureAlgorithm.dsa));
			v.addElement(Shorts.valueOf(SignatureAlgorithm.ecdsa));
			return v;
		}

		public static Vector getDefaultDSSSignatureAlgorithms()
		{
			return vectorOfOne(new SignatureAndHashAlgorithm(HashAlgorithm.sha1, SignatureAlgorithm.dsa));
		}

		public static Vector getDefaultECDSASignatureAlgorithms()
		{
			return vectorOfOne(new SignatureAndHashAlgorithm(HashAlgorithm.sha1, SignatureAlgorithm.ecdsa));
		}

		public static Vector getDefaultRSASignatureAlgorithms()
		{
			return vectorOfOne(new SignatureAndHashAlgorithm(HashAlgorithm.sha1, SignatureAlgorithm.rsa));
		}

		public static Vector getDefaultSupportedSignatureAlgorithms()
		{
			short[] hashAlgorithms = new short[]{HashAlgorithm.sha1, HashAlgorithm.sha224, HashAlgorithm.sha256, HashAlgorithm.sha384, HashAlgorithm.sha512};
			short[] signatureAlgorithms = new short[]{SignatureAlgorithm.rsa, SignatureAlgorithm.dsa, SignatureAlgorithm.ecdsa};

			Vector result = new Vector();
			for (int i = 0; i < signatureAlgorithms.Length; ++i)
			{
				for (int j = 0; j < hashAlgorithms.Length; ++j)
				{
					result.addElement(new SignatureAndHashAlgorithm(hashAlgorithms[j], signatureAlgorithms[i]));
				}
			}
			return result;
		}

		public static SignatureAndHashAlgorithm getSignatureAndHashAlgorithm(TlsContext context, TlsSignerCredentials signerCredentials)
		{
			SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;
			if (isTLSv12(context))
			{
				signatureAndHashAlgorithm = signerCredentials.getSignatureAndHashAlgorithm();
				if (signatureAndHashAlgorithm == null)
				{
					throw new TlsFatalAlert(AlertDescription.internal_error);
				}
			}
			return signatureAndHashAlgorithm;
		}

		public static byte[] getExtensionData(Hashtable extensions, int? extensionType)
		{
			return extensions == null ? null : (byte[])extensions.get(extensionType);
		}

		public static bool hasExpectedEmptyExtensionData(Hashtable extensions, int? extensionType, short alertDescription)
		{
			byte[] extension_data = getExtensionData(extensions, extensionType);
			if (extension_data == null)
			{
				return false;
			}
			if (extension_data.Length != 0)
			{
				throw new TlsFatalAlert(alertDescription);
			}
			return true;
		}

		public static TlsSession importSession(byte[] sessionID, SessionParameters sessionParameters)
		{
			return new TlsSessionImpl(sessionID, sessionParameters);
		}

		public static bool isSignatureAlgorithmsExtensionAllowed(ProtocolVersion clientVersion)
		{
			return ProtocolVersion.TLSv12.isEqualOrEarlierVersionOf(clientVersion.getEquivalentTLSVersion());
		}

		/// <summary>
		/// Add a 'signature_algorithms' extension to existing extensions.
		/// </summary>
		/// <param name="extensions">                   A <seealso cref="Hashtable"/> to add the extension to. </param>
		/// <param name="supportedSignatureAlgorithms"> <seealso cref="Vector"/> containing at least 1 <seealso cref="SignatureAndHashAlgorithm"/>. </param>
		/// <exception cref="IOException"> </exception>
		public static void addSignatureAlgorithmsExtension(Hashtable extensions, Vector supportedSignatureAlgorithms)
		{
			extensions.put(EXT_signature_algorithms, createSignatureAlgorithmsExtension(supportedSignatureAlgorithms));
		}

		/// <summary>
		/// Get a 'signature_algorithms' extension from extensions.
		/// </summary>
		/// <param name="extensions"> A <seealso cref="Hashtable"/> to get the extension from, if it is present. </param>
		/// <returns> A <seealso cref="Vector"/> containing at least 1 <seealso cref="SignatureAndHashAlgorithm"/>, or null. </returns>
		/// <exception cref="IOException"> </exception>
		public static Vector getSignatureAlgorithmsExtension(Hashtable extensions)
		{
			byte[] extensionData = getExtensionData(extensions, EXT_signature_algorithms);
			return extensionData == null ? null : readSignatureAlgorithmsExtension(extensionData);
		}

		/// <summary>
		/// Create a 'signature_algorithms' extension value.
		/// </summary>
		/// <param name="supportedSignatureAlgorithms"> A <seealso cref="Vector"/> containing at least 1 <seealso cref="SignatureAndHashAlgorithm"/>. </param>
		/// <returns> A byte array suitable for use as an extension value. </returns>
		/// <exception cref="IOException"> </exception>
		public static byte[] createSignatureAlgorithmsExtension(Vector supportedSignatureAlgorithms)
		{
			ByteArrayOutputStream buf = new ByteArrayOutputStream();

			// supported_signature_algorithms
			encodeSupportedSignatureAlgorithms(supportedSignatureAlgorithms, false, buf);

			return buf.toByteArray();
		}

		/// <summary>
		/// Read 'signature_algorithms' extension data.
		/// </summary>
		/// <param name="extensionData"> The extension data. </param>
		/// <returns> A <seealso cref="Vector"/> containing at least 1 <seealso cref="SignatureAndHashAlgorithm"/>. </returns>
		/// <exception cref="IOException"> </exception>
		public static Vector readSignatureAlgorithmsExtension(byte[] extensionData)
		{
			if (extensionData == null)
			{
				throw new IllegalArgumentException("'extensionData' cannot be null");
			}

			ByteArrayInputStream buf = new ByteArrayInputStream(extensionData);

			// supported_signature_algorithms
			Vector supported_signature_algorithms = parseSupportedSignatureAlgorithms(false, buf);

			TlsProtocol.assertEmpty(buf);

			return supported_signature_algorithms;
		}

		public static void encodeSupportedSignatureAlgorithms(Vector supportedSignatureAlgorithms, bool allowAnonymous, OutputStream output)
		{
			if (supportedSignatureAlgorithms == null || supportedSignatureAlgorithms.size() < 1 || supportedSignatureAlgorithms.size() >= (1 << 15))
			{
				throw new IllegalArgumentException("'supportedSignatureAlgorithms' must have length from 1 to (2^15 - 1)");
			}

			// supported_signature_algorithms
			int length = 2 * supportedSignatureAlgorithms.size();
			checkUint16(length);
			writeUint16(length, output);
			for (int i = 0; i < supportedSignatureAlgorithms.size(); ++i)
			{
				SignatureAndHashAlgorithm entry = (SignatureAndHashAlgorithm)supportedSignatureAlgorithms.elementAt(i);
				if (!allowAnonymous && entry.getSignature() == SignatureAlgorithm.anonymous)
				{
					/*
					 * RFC 5246 7.4.1.4.1 The "anonymous" value is meaningless in this context but used
					 * in Section 7.4.3. It MUST NOT appear in this extension.
					 */
					throw new IllegalArgumentException("SignatureAlgorithm.anonymous MUST NOT appear in the signature_algorithms extension");
				}
				entry.encode(output);
			}
		}

		public static Vector parseSupportedSignatureAlgorithms(bool allowAnonymous, InputStream input)
		{
			// supported_signature_algorithms
			int length = readUint16(input);
			if (length < 2 || (length & 1) != 0)
			{
				throw new TlsFatalAlert(AlertDescription.decode_error);
			}
			int count = length / 2;
			Vector supportedSignatureAlgorithms = new Vector(count);
			for (int i = 0; i < count; ++i)
			{
				SignatureAndHashAlgorithm entry = SignatureAndHashAlgorithm.parse(input);
				if (!allowAnonymous && entry.getSignature() == SignatureAlgorithm.anonymous)
				{
					/*
					 * RFC 5246 7.4.1.4.1 The "anonymous" value is meaningless in this context but used
					 * in Section 7.4.3. It MUST NOT appear in this extension.
					 */
					throw new TlsFatalAlert(AlertDescription.illegal_parameter);
				}
				supportedSignatureAlgorithms.addElement(entry);
			}
			return supportedSignatureAlgorithms;
		}

		public static void verifySupportedSignatureAlgorithm(Vector supportedSignatureAlgorithms, SignatureAndHashAlgorithm signatureAlgorithm)
		{
			if (supportedSignatureAlgorithms == null || supportedSignatureAlgorithms.size() < 1 || supportedSignatureAlgorithms.size() >= (1 << 15))
			{
				throw new IllegalArgumentException("'supportedSignatureAlgorithms' must have length from 1 to (2^15 - 1)");
			}
			if (signatureAlgorithm == null)
			{
				throw new IllegalArgumentException("'signatureAlgorithm' cannot be null");
			}

			if (signatureAlgorithm.getSignature() != SignatureAlgorithm.anonymous)
			{
				for (int i = 0; i < supportedSignatureAlgorithms.size(); ++i)
				{
					SignatureAndHashAlgorithm entry = (SignatureAndHashAlgorithm)supportedSignatureAlgorithms.elementAt(i);
					if (entry.getHash() == signatureAlgorithm.getHash() && entry.getSignature() == signatureAlgorithm.getSignature())
					{
						return;
					}
				}
			}

			throw new TlsFatalAlert(AlertDescription.illegal_parameter);
		}

		public static byte[] PRF(TlsContext context, byte[] secret, string asciiLabel, byte[] seed, int size)
		{
			ProtocolVersion version = context.getServerVersion();

			if (version.isSSL())
			{
				throw new IllegalStateException("No PRF available for SSLv3 session");
			}

			byte[] label = Strings.toByteArray(asciiLabel);
			byte[] labelSeed = concat(label, seed);

			int prfAlgorithm = context.getSecurityParameters().getPrfAlgorithm();

			if (prfAlgorithm == PRFAlgorithm.tls_prf_legacy)
			{
				return PRF_legacy(secret, label, labelSeed, size);
			}

			Digest prfDigest = createPRFHash(prfAlgorithm);
			byte[] buf = new byte[size];
			hmac_hash(prfDigest, secret, labelSeed, buf);
			return buf;
		}

		public static byte[] PRF_legacy(byte[] secret, string asciiLabel, byte[] seed, int size)
		{
			byte[] label = Strings.toByteArray(asciiLabel);
			byte[] labelSeed = concat(label, seed);

			return PRF_legacy(secret, label, labelSeed, size);
		}

		internal static byte[] PRF_legacy(byte[] secret, byte[] label, byte[] labelSeed, int size)
		{
			int s_half = (secret.Length + 1) / 2;
			byte[] s1 = new byte[s_half];
			byte[] s2 = new byte[s_half];
			JavaSystem.arraycopy(secret, 0, s1, 0, s_half);
			JavaSystem.arraycopy(secret, secret.Length - s_half, s2, 0, s_half);

			byte[] b1 = new byte[size];
			byte[] b2 = new byte[size];
			hmac_hash(createHash(HashAlgorithm.md5), s1, labelSeed, b1);
			hmac_hash(createHash(HashAlgorithm.sha1), s2, labelSeed, b2);
			for (int i = 0; i < size; i++)
			{
				b1[i] ^= b2[i];
			}
			return b1;
		}

		internal static byte[] concat(byte[] a, byte[] b)
		{
			byte[] c = new byte[a.Length + b.Length];
			JavaSystem.arraycopy(a, 0, c, 0, a.Length);
			JavaSystem.arraycopy(b, 0, c, a.Length, b.Length);
			return c;
		}

		internal static void hmac_hash(Digest digest, byte[] secret, byte[] seed, byte[] @out)
		{
			HMac mac = new HMac(digest);
			mac.init(new KeyParameter(secret));
			byte[] a = seed;
			int size = digest.getDigestSize();
			int iterations = (@out.Length + size - 1) / size;
			byte[] buf = new byte[mac.getMacSize()];
			byte[] buf2 = new byte[mac.getMacSize()];
			for (int i = 0; i < iterations; i++)
			{
				mac.update(a, 0, a.Length);
				mac.doFinal(buf, 0);
				a = buf;
				mac.update(a, 0, a.Length);
				mac.update(seed, 0, seed.Length);
				mac.doFinal(buf2, 0);
				JavaSystem.arraycopy(buf2, 0, @out, (size * i), Math.Min(size, @out.Length - (size * i)));
			}
		}

		internal static void validateKeyUsage(org.bouncycastle.asn1.x509.Certificate c, int keyUsageBits)
		{
			Extensions exts = c.getTBSCertificate().getExtensions();
			if (exts != null)
			{
				KeyUsage ku = KeyUsage.fromExtensions(exts);
				if (ku != null)
				{
					int bits = ku.getBytes()[0] & 0xff;
					if ((bits & keyUsageBits) != keyUsageBits)
					{
						throw new TlsFatalAlert(AlertDescription.certificate_unknown);
					}
				}
			}
		}

		internal static byte[] calculateKeyBlock(TlsContext context, int size)
		{
			SecurityParameters securityParameters = context.getSecurityParameters();
			byte[] master_secret = securityParameters.getMasterSecret();
			byte[] seed = concat(securityParameters.getServerRandom(), securityParameters.getClientRandom());

			if (isSSL(context))
			{
				return calculateKeyBlock_SSL(master_secret, seed, size);
			}

			return PRF(context, master_secret, ExporterLabel.key_expansion, seed, size);
		}

		internal static byte[] calculateKeyBlock_SSL(byte[] master_secret, byte[] random, int size)
		{
			Digest md5 = createHash(HashAlgorithm.md5);
			Digest sha1 = createHash(HashAlgorithm.sha1);
			int md5Size = md5.getDigestSize();
			byte[] shatmp = new byte[sha1.getDigestSize()];
			byte[] tmp = new byte[size + md5Size];

			int i = 0, pos = 0;
			while (pos < size)
			{
				byte[] ssl3Const = SSL3_CONST[i];

				sha1.update(ssl3Const, 0, ssl3Const.Length);
				sha1.update(master_secret, 0, master_secret.Length);
				sha1.update(random, 0, random.Length);
				sha1.doFinal(shatmp, 0);

				md5.update(master_secret, 0, master_secret.Length);
				md5.update(shatmp, 0, shatmp.Length);
				md5.doFinal(tmp, pos);

				pos += md5Size;
				++i;
			}

			return Arrays.copyOfRange(tmp, 0, size);
		}

		internal static byte[] calculateMasterSecret(TlsContext context, byte[] pre_master_secret)
		{
			SecurityParameters securityParameters = context.getSecurityParameters();

			byte[] seed;
			if (securityParameters.isExtendedMasterSecret())
			{
				seed = securityParameters.getSessionHash();
			}
			else
			{
				seed = concat(securityParameters.getClientRandom(), securityParameters.getServerRandom());
			}

			if (isSSL(context))
			{
				return calculateMasterSecret_SSL(pre_master_secret, seed);
			}

			string asciiLabel = securityParameters.isExtendedMasterSecret() ? ExporterLabel.extended_master_secret : ExporterLabel.master_secret;

			return PRF(context, pre_master_secret, asciiLabel, seed, 48);
		}

		internal static byte[] calculateMasterSecret_SSL(byte[] pre_master_secret, byte[] random)
		{
			Digest md5 = createHash(HashAlgorithm.md5);
			Digest sha1 = createHash(HashAlgorithm.sha1);
			int md5Size = md5.getDigestSize();
			byte[] shatmp = new byte[sha1.getDigestSize()];

			byte[] rval = new byte[md5Size * 3];
			int pos = 0;

			for (int i = 0; i < 3; ++i)
			{
				byte[] ssl3Const = SSL3_CONST[i];

				sha1.update(ssl3Const, 0, ssl3Const.Length);
				sha1.update(pre_master_secret, 0, pre_master_secret.Length);
				sha1.update(random, 0, random.Length);
				sha1.doFinal(shatmp, 0);

				md5.update(pre_master_secret, 0, pre_master_secret.Length);
				md5.update(shatmp, 0, shatmp.Length);
				md5.doFinal(rval, pos);

				pos += md5Size;
			}

			return rval;
		}

		internal static byte[] calculateVerifyData(TlsContext context, string asciiLabel, byte[] handshakeHash)
		{
			if (isSSL(context))
			{
				return handshakeHash;
			}

			SecurityParameters securityParameters = context.getSecurityParameters();
			byte[] master_secret = securityParameters.getMasterSecret();
			int verify_data_length = securityParameters.getVerifyDataLength();

			return PRF(context, master_secret, asciiLabel, handshakeHash, verify_data_length);
		}

		public static Digest createHash(short hashAlgorithm)
		{
			switch (hashAlgorithm)
			{
			case HashAlgorithm.md5:
				return new MD5Digest();
			case HashAlgorithm.sha1:
				return new SHA1Digest();
			case HashAlgorithm.sha224:
				return new SHA224Digest();
			case HashAlgorithm.sha256:
				return new SHA256Digest();
			case HashAlgorithm.sha384:
				return new SHA384Digest();
			case HashAlgorithm.sha512:
				return new SHA512Digest();
			default:
				throw new IllegalArgumentException("unknown HashAlgorithm");
			}
		}

		public static Digest createHash(SignatureAndHashAlgorithm signatureAndHashAlgorithm)
		{
			return signatureAndHashAlgorithm == null ? new CombinedHash() : createHash(signatureAndHashAlgorithm.getHash());
		}

		public static Digest cloneHash(short hashAlgorithm, Digest hash)
		{
			switch (hashAlgorithm)
			{
			case HashAlgorithm.md5:
				return new MD5Digest((MD5Digest)hash);
			case HashAlgorithm.sha1:
				return new SHA1Digest((SHA1Digest)hash);
			case HashAlgorithm.sha224:
				return new SHA224Digest((SHA224Digest)hash);
			case HashAlgorithm.sha256:
				return new SHA256Digest((SHA256Digest)hash);
			case HashAlgorithm.sha384:
				return new SHA384Digest((SHA384Digest)hash);
			case HashAlgorithm.sha512:
				return new SHA512Digest((SHA512Digest)hash);
			default:
				throw new IllegalArgumentException("unknown HashAlgorithm");
			}
		}

		public static Digest createPRFHash(int prfAlgorithm)
		{
			switch (prfAlgorithm)
			{
			case PRFAlgorithm.tls_prf_legacy:
				return new CombinedHash();
			default:
				return createHash(getHashAlgorithmForPRFAlgorithm(prfAlgorithm));
			}
		}

		public static Digest clonePRFHash(int prfAlgorithm, Digest hash)
		{
			switch (prfAlgorithm)
			{
			case PRFAlgorithm.tls_prf_legacy:
				return new CombinedHash((CombinedHash)hash);
			default:
				return cloneHash(getHashAlgorithmForPRFAlgorithm(prfAlgorithm), hash);
			}
		}

		public static short getHashAlgorithmForPRFAlgorithm(int prfAlgorithm)
		{
			switch (prfAlgorithm)
			{
			case PRFAlgorithm.tls_prf_legacy:
				throw new IllegalArgumentException("legacy PRF not a valid algorithm");
			case PRFAlgorithm.tls_prf_sha256:
				return HashAlgorithm.sha256;
			case PRFAlgorithm.tls_prf_sha384:
				return HashAlgorithm.sha384;
			default:
				throw new IllegalArgumentException("unknown PRFAlgorithm");
			}
		}

		public static ASN1ObjectIdentifier getOIDForHashAlgorithm(short hashAlgorithm)
		{
			switch (hashAlgorithm)
			{
			case HashAlgorithm.md5:
				return PKCSObjectIdentifiers_Fields.md5;
			case HashAlgorithm.sha1:
				return X509ObjectIdentifiers_Fields.id_SHA1;
			case HashAlgorithm.sha224:
				return NISTObjectIdentifiers_Fields.id_sha224;
			case HashAlgorithm.sha256:
				return NISTObjectIdentifiers_Fields.id_sha256;
			case HashAlgorithm.sha384:
				return NISTObjectIdentifiers_Fields.id_sha384;
			case HashAlgorithm.sha512:
				return NISTObjectIdentifiers_Fields.id_sha512;
			default:
				throw new IllegalArgumentException("unknown HashAlgorithm");
			}
		}

		internal static short getClientCertificateType(Certificate clientCertificate, Certificate serverCertificate)
		{
			if (clientCertificate.isEmpty())
			{
				return -1;
			}

		    org.bouncycastle.asn1.x509.Certificate x509Cert = clientCertificate.getCertificateAt(0);
			SubjectPublicKeyInfo keyInfo = x509Cert.getSubjectPublicKeyInfo();
			try
			{
				AsymmetricKeyParameter publicKey = PublicKeyFactory.createKey(keyInfo);
				if (publicKey.isPrivate())
				{
					throw new TlsFatalAlert(AlertDescription.internal_error);
				}

				/*
				 * TODO RFC 5246 7.4.6. The certificates MUST be signed using an acceptable hash/
				 * signature algorithm pair, as described in Section 7.4.4. Note that this relaxes the
				 * constraints on certificate-signing algorithms found in prior versions of TLS.
				 */

				/*
				 * RFC 5246 7.4.6. Client Certificate
				 */

				/*
				 * RSA public key; the certificate MUST allow the key to be used for signing with the
				 * signature scheme and hash algorithm that will be employed in the certificate verify
				 * message.
				 */
				if (publicKey is RSAKeyParameters)
				{
					validateKeyUsage(x509Cert, KeyUsage.digitalSignature);
					return ClientCertificateType.rsa_sign;
				}

				/*
				 * DSA public key; the certificate MUST allow the key to be used for signing with the
				 * hash algorithm that will be employed in the certificate verify message.
				 */
				if (publicKey is DSAPublicKeyParameters)
				{
					validateKeyUsage(x509Cert, KeyUsage.digitalSignature);
					return ClientCertificateType.dss_sign;
				}

				/*
				 * ECDSA-capable public key; the certificate MUST allow the key to be used for signing
				 * with the hash algorithm that will be employed in the certificate verify message; the
				 * public key MUST use a curve and point format supported by the server.
				 */
				if (publicKey is ECPublicKeyParameters)
				{
					validateKeyUsage(x509Cert, KeyUsage.digitalSignature);
					// TODO Check the curve and point format
					return ClientCertificateType.ecdsa_sign;
				}

				// TODO Add support for ClientCertificateType.*_fixed_*

				throw new TlsFatalAlert(AlertDescription.unsupported_certificate);
			}
			catch (Exception e)
			{
				throw new TlsFatalAlert(AlertDescription.unsupported_certificate, e);
			}
		}

		internal static void trackHashAlgorithms(TlsHandshakeHash handshakeHash, Vector supportedSignatureAlgorithms)
		{
			if (supportedSignatureAlgorithms != null)
			{
				for (int i = 0; i < supportedSignatureAlgorithms.size(); ++i)
				{
					SignatureAndHashAlgorithm signatureAndHashAlgorithm = (SignatureAndHashAlgorithm) supportedSignatureAlgorithms.elementAt(i);
					short hashAlgorithm = signatureAndHashAlgorithm.getHash();

					if (HashAlgorithm.isRecognized(hashAlgorithm))
					{
						handshakeHash.trackHashAlgorithm(hashAlgorithm);
					}
					else //if (HashAlgorithm.isPrivate(hashAlgorithm))
					{
						// TODO Support values in the "Reserved for Private Use" range
					}
				}
			}
		}

		public static bool hasSigningCapability(short clientCertificateType)
		{
			switch (clientCertificateType)
			{
			case ClientCertificateType.dss_sign:
			case ClientCertificateType.ecdsa_sign:
			case ClientCertificateType.rsa_sign:
				return true;
			default:
				return false;
			}
		}

		public static TlsSigner createTlsSigner(short clientCertificateType)
		{
			switch (clientCertificateType)
			{
			case ClientCertificateType.dss_sign:
				return new TlsDSSSigner();
			case ClientCertificateType.ecdsa_sign:
				return new TlsECDSASigner();
			case ClientCertificateType.rsa_sign:
				return new TlsRSASigner();
			default:
				throw new IllegalArgumentException("'clientCertificateType' is not a type with signing capability");
			}
		}

		internal static readonly byte[] SSL_CLIENT = new byte[] {0x43, 0x4C, 0x4E, 0x54};
		internal static readonly byte[] SSL_SERVER = new byte[] {0x53, 0x52, 0x56, 0x52};

		// SSL3 magic mix constants ("A", "BB", "CCC", ...)
		internal static readonly byte[][] SSL3_CONST = genSSL3Const();

		private static byte[][] genSSL3Const()
		{
			int n = 10;
			byte[][] arr = new byte[n][];
			for (int i = 0; i < n; i++)
			{
				byte[] b = new byte[i + 1];
				Arrays.fill(b, (byte)('A' + i));
				arr[i] = b;
			}
			return arr;
		}

		private static Vector vectorOfOne(object obj)
		{
			Vector v = new Vector(1);
			v.addElement(obj);
			return v;
		}

		public static int getCipherType(int ciphersuite)
		{
			switch (getEncryptionAlgorithm(ciphersuite))
			{
			case EncryptionAlgorithm.AES_128_CCM:
			case EncryptionAlgorithm.AES_128_CCM_8:
			case EncryptionAlgorithm.AES_128_GCM:
			case EncryptionAlgorithm.AES_128_OCB_TAGLEN96:
			case EncryptionAlgorithm.AES_256_CCM:
			case EncryptionAlgorithm.AES_256_CCM_8:
			case EncryptionAlgorithm.AES_256_GCM:
			case EncryptionAlgorithm.AES_256_OCB_TAGLEN96:
			case EncryptionAlgorithm.CAMELLIA_128_GCM:
			case EncryptionAlgorithm.CAMELLIA_256_GCM:
			case EncryptionAlgorithm.CHACHA20_POLY1305:
				return CipherType.aead;

			case EncryptionAlgorithm.RC2_CBC_40:
			case EncryptionAlgorithm.IDEA_CBC:
			case EncryptionAlgorithm.DES40_CBC:
			case EncryptionAlgorithm.DES_CBC:
			case EncryptionAlgorithm._3DES_EDE_CBC:
			case EncryptionAlgorithm.AES_128_CBC:
			case EncryptionAlgorithm.AES_256_CBC:
			case EncryptionAlgorithm.CAMELLIA_128_CBC:
			case EncryptionAlgorithm.CAMELLIA_256_CBC:
			case EncryptionAlgorithm.SEED_CBC:
				return CipherType.block;

			case EncryptionAlgorithm.NULL:
			case EncryptionAlgorithm.RC4_40:
			case EncryptionAlgorithm.RC4_128:
				return CipherType.stream;

			default:
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}
		}

		public static int getEncryptionAlgorithm(int ciphersuite)
		{
			switch (ciphersuite)
			{
			case CipherSuite.TLS_DH_anon_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
				return EncryptionAlgorithm._3DES_EDE_CBC;

			case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_ECDH_anon_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA:
				return EncryptionAlgorithm.AES_128_CBC;

			case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
			case CipherSuite.TLS_PSK_WITH_AES_128_CCM:
			case CipherSuite.TLS_RSA_WITH_AES_128_CCM:
				return EncryptionAlgorithm.AES_128_CCM;

			case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
			case CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8:
			case CipherSuite.TLS_PSK_WITH_AES_128_CCM_8:
			case CipherSuite.TLS_RSA_WITH_AES_128_CCM_8:
				return EncryptionAlgorithm.AES_128_CCM_8;

			case CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
				return EncryptionAlgorithm.AES_128_GCM;

			case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_AES_128_OCB:
			case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_AES_128_OCB:
			case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_AES_128_OCB:
			case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_OCB:
			case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_128_OCB:
			case CipherSuite.DRAFT_TLS_PSK_WITH_AES_128_OCB:
				return EncryptionAlgorithm.AES_128_OCB_TAGLEN96;

			case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_ECDH_anon_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA:
				return EncryptionAlgorithm.AES_256_CBC;

			case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM:
			case CipherSuite.TLS_PSK_WITH_AES_256_CCM:
			case CipherSuite.TLS_RSA_WITH_AES_256_CCM:
				return EncryptionAlgorithm.AES_256_CCM;

			case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:
			case CipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_8:
			case CipherSuite.TLS_PSK_WITH_AES_256_CCM_8:
			case CipherSuite.TLS_RSA_WITH_AES_256_CCM_8:
				return EncryptionAlgorithm.AES_256_CCM_8;

			case CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384:
				return EncryptionAlgorithm.AES_256_GCM;

			case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_AES_256_OCB:
			case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_AES_256_OCB:
			case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_AES_256_OCB:
			case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_256_OCB:
			case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_256_OCB:
			case CipherSuite.DRAFT_TLS_PSK_WITH_AES_256_OCB:
				return EncryptionAlgorithm.AES_256_OCB_TAGLEN96;

			case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA:
			case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA:
			case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA:
			case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA:
			case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA:
			case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA:
			case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256:
				return EncryptionAlgorithm.CAMELLIA_128_CBC;

			case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256:
				return EncryptionAlgorithm.CAMELLIA_128_GCM;

			case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA:
			case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA:
			case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA:
			case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA:
			case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA:
			case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA:
			case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384:
				return EncryptionAlgorithm.CAMELLIA_256_CBC;

			case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384:
				return EncryptionAlgorithm.CAMELLIA_256_GCM;

			case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.DRAFT_TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.DRAFT_TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256:
				return EncryptionAlgorithm.CHACHA20_POLY1305;

			case CipherSuite.TLS_RSA_WITH_NULL_MD5:
				return EncryptionAlgorithm.NULL;

			case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA:
			case CipherSuite.TLS_ECDH_anon_WITH_NULL_SHA:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_NULL_SHA:
			case CipherSuite.TLS_ECDH_RSA_WITH_NULL_SHA:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA:
			case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA:
			case CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA:
			case CipherSuite.TLS_PSK_WITH_NULL_SHA:
			case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA:
			case CipherSuite.TLS_RSA_WITH_NULL_SHA:
				return EncryptionAlgorithm.NULL;

			case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA256:
			case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA256:
			case CipherSuite.TLS_PSK_WITH_NULL_SHA256:
			case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA256:
			case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
				return EncryptionAlgorithm.NULL;

			case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA384:
			case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA384:
			case CipherSuite.TLS_PSK_WITH_NULL_SHA384:
			case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA384:
				return EncryptionAlgorithm.NULL;

			case CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5:
			case CipherSuite.TLS_RSA_WITH_RC4_128_MD5:
				return EncryptionAlgorithm.RC4_128;

			case CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA:
			case CipherSuite.TLS_ECDH_anon_WITH_RC4_128_SHA:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
			case CipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
			case CipherSuite.TLS_ECDHE_PSK_WITH_RC4_128_SHA:
			case CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
			case CipherSuite.TLS_PSK_WITH_RC4_128_SHA:
			case CipherSuite.TLS_RSA_WITH_RC4_128_SHA:
			case CipherSuite.TLS_RSA_PSK_WITH_RC4_128_SHA:
				return EncryptionAlgorithm.RC4_128;

			case CipherSuite.TLS_DH_anon_WITH_SEED_CBC_SHA:
			case CipherSuite.TLS_DH_DSS_WITH_SEED_CBC_SHA:
			case CipherSuite.TLS_DH_RSA_WITH_SEED_CBC_SHA:
			case CipherSuite.TLS_DHE_DSS_WITH_SEED_CBC_SHA:
			case CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA:
			case CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA:
				return EncryptionAlgorithm.SEED_CBC;

			default:
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}
		}

		public static int getKeyExchangeAlgorithm(int ciphersuite)
		{
			switch (ciphersuite)
			{
			case CipherSuite.TLS_DH_anon_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA:
			case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA:
			case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5:
			case CipherSuite.TLS_DH_anon_WITH_SEED_CBC_SHA:
				return KeyExchangeAlgorithm.DH_anon;

			case CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA:
			case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA:
			case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_DH_DSS_WITH_SEED_CBC_SHA:
				return KeyExchangeAlgorithm.DH_DSS;

			case CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA:
			case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA:
			case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_DH_RSA_WITH_SEED_CBC_SHA:
				return KeyExchangeAlgorithm.DH_RSA;

			case CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA:
			case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA:
			case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_DHE_DSS_WITH_SEED_CBC_SHA:
				return KeyExchangeAlgorithm.DHE_DSS;

			case CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM:
			case CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
			case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_AES_128_OCB:
			case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM:
			case CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_AES_256_OCB:
			case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA:
			case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA256:
			case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA384:
			case CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA:
			case CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8:
			case CipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_8:
				return KeyExchangeAlgorithm.DHE_PSK;

			case CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_AES_128_OCB:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_AES_256_OCB:
			case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA:
			case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA:
			case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA:
				return KeyExchangeAlgorithm.DHE_RSA;

			case CipherSuite.TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_ECDH_anon_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_ECDH_anon_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_ECDH_anon_WITH_NULL_SHA:
			case CipherSuite.TLS_ECDH_anon_WITH_RC4_128_SHA:
				return KeyExchangeAlgorithm.ECDH_anon;

			case CipherSuite.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_NULL_SHA:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
				return KeyExchangeAlgorithm.ECDH_ECDSA;

			case CipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_ECDH_RSA_WITH_NULL_SHA:
			case CipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA:
				return KeyExchangeAlgorithm.ECDH_RSA;

			case CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_AES_128_OCB:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_AES_256_OCB:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
				return KeyExchangeAlgorithm.ECDHE_ECDSA;

			case CipherSuite.TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:
			case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_OCB:
			case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384:
			case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_256_OCB:
			case CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA:
			case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA256:
			case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA384:
			case CipherSuite.TLS_ECDHE_PSK_WITH_RC4_128_SHA:
				return KeyExchangeAlgorithm.ECDHE_PSK;

			case CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_128_OCB:
			case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_256_OCB:
			case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA:
			case CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
				return KeyExchangeAlgorithm.ECDHE_RSA;

			case CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_PSK_WITH_AES_128_CCM:
			case CipherSuite.TLS_PSK_WITH_AES_128_CCM_8:
			case CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256:
			case CipherSuite.DRAFT_TLS_PSK_WITH_AES_128_OCB:
			case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_PSK_WITH_AES_256_CCM:
			case CipherSuite.TLS_PSK_WITH_AES_256_CCM_8:
			case CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_PSK_WITH_AES_256_OCB:
			case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.TLS_PSK_WITH_NULL_SHA:
			case CipherSuite.TLS_PSK_WITH_NULL_SHA256:
			case CipherSuite.TLS_PSK_WITH_NULL_SHA384:
			case CipherSuite.TLS_PSK_WITH_RC4_128_SHA:
				return KeyExchangeAlgorithm.PSK;

			case CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_RSA_WITH_AES_128_CCM:
			case CipherSuite.TLS_RSA_WITH_AES_128_CCM_8:
			case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_RSA_WITH_AES_256_CCM:
			case CipherSuite.TLS_RSA_WITH_AES_256_CCM_8:
			case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA:
			case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA:
			case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_RSA_WITH_NULL_MD5:
			case CipherSuite.TLS_RSA_WITH_NULL_SHA:
			case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
			case CipherSuite.TLS_RSA_WITH_RC4_128_MD5:
			case CipherSuite.TLS_RSA_WITH_RC4_128_SHA:
			case CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA:
				return KeyExchangeAlgorithm.RSA;

			case CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA:
			case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA256:
			case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA384:
			case CipherSuite.TLS_RSA_PSK_WITH_RC4_128_SHA:
				return KeyExchangeAlgorithm.RSA_PSK;

			case CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA:
				return KeyExchangeAlgorithm.SRP;

			case CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
				return KeyExchangeAlgorithm.SRP_DSS;

			case CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
				return KeyExchangeAlgorithm.SRP_RSA;

			default:
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}
		}

		public static int getMACAlgorithm(int ciphersuite)
		{
			switch (ciphersuite)
			{
			case CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM:
			case CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
			case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_AES_128_OCB:
			case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM:
			case CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_AES_256_OCB:
			case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_AES_128_OCB:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_AES_256_OCB:
			case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_AES_128_OCB:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_AES_256_OCB:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_OCB:
			case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_256_OCB:
			case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_128_OCB:
			case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_256_OCB:
			case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8:
			case CipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_8:
			case CipherSuite.TLS_PSK_WITH_AES_128_CCM:
			case CipherSuite.TLS_PSK_WITH_AES_128_CCM_8:
			case CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256:
			case CipherSuite.DRAFT_TLS_PSK_WITH_AES_128_OCB:
			case CipherSuite.TLS_PSK_WITH_AES_256_CCM:
			case CipherSuite.TLS_PSK_WITH_AES_256_CCM_8:
			case CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_PSK_WITH_AES_256_OCB:
			case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.TLS_RSA_WITH_AES_128_CCM:
			case CipherSuite.TLS_RSA_WITH_AES_128_CCM_8:
			case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_RSA_WITH_AES_256_CCM:
			case CipherSuite.TLS_RSA_WITH_AES_256_CCM_8:
			case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384:
				return MACAlgorithm._null;

			case CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5:
			case CipherSuite.TLS_RSA_WITH_NULL_MD5:
			case CipherSuite.TLS_RSA_WITH_RC4_128_MD5:
				return MACAlgorithm.hmac_md5;

			case CipherSuite.TLS_DH_anon_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA:
			case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA:
			case CipherSuite.TLS_DH_anon_WITH_SEED_CBC_SHA:
			case CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA:
			case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA:
			case CipherSuite.TLS_DH_DSS_WITH_SEED_CBC_SHA:
			case CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA:
			case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA:
			case CipherSuite.TLS_DH_RSA_WITH_SEED_CBC_SHA:
			case CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA:
			case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA:
			case CipherSuite.TLS_DHE_DSS_WITH_SEED_CBC_SHA:
			case CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA:
			case CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA:
			case CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA:
			case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA:
			case CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA:
			case CipherSuite.TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_ECDH_anon_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_ECDH_anon_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_ECDH_anon_WITH_NULL_SHA:
			case CipherSuite.TLS_ECDH_anon_WITH_RC4_128_SHA:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_NULL_SHA:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
			case CipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_ECDH_RSA_WITH_NULL_SHA:
			case CipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
			case CipherSuite.TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA:
			case CipherSuite.TLS_ECDHE_PSK_WITH_RC4_128_SHA:
			case CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA:
			case CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
			case CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_PSK_WITH_NULL_SHA:
			case CipherSuite.TLS_PSK_WITH_RC4_128_SHA:
			case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA:
			case CipherSuite.TLS_RSA_PSK_WITH_RC4_128_SHA:
			case CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA:
			case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA:
			case CipherSuite.TLS_RSA_WITH_NULL_SHA:
			case CipherSuite.TLS_RSA_WITH_RC4_128_SHA:
			case CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA:
			case CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
			case CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
			case CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA:
			case CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA:
				return MACAlgorithm.hmac_sha1;

			case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA256:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA256:
			case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_PSK_WITH_NULL_SHA256:
			case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA256:
			case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
				return MACAlgorithm.hmac_sha256;

			case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA384:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA384:
			case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_PSK_WITH_NULL_SHA384:
			case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA384:
				return MACAlgorithm.hmac_sha384;

			default:
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}
		}

		public static ProtocolVersion getMinimumVersion(int ciphersuite)
		{
			switch (ciphersuite)
			{
			case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM:
			case CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
			case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_AES_128_OCB:
			case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM:
			case CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_AES_256_OCB:
			case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_AES_128_OCB:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8:
			case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_AES_256_OCB:
			case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_AES_128_OCB:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_AES_256_OCB:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_OCB:
			case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_256_OCB:
			case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_128_OCB:
			case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
			case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_256_OCB:
			case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384:
			case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8:
			case CipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_8:
			case CipherSuite.TLS_PSK_WITH_AES_128_CCM:
			case CipherSuite.TLS_PSK_WITH_AES_128_CCM_8:
			case CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256:
			case CipherSuite.DRAFT_TLS_PSK_WITH_AES_128_OCB:
			case CipherSuite.TLS_PSK_WITH_AES_256_CCM:
			case CipherSuite.TLS_PSK_WITH_AES_256_CCM_8:
			case CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_PSK_WITH_AES_256_OCB:
			case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.DRAFT_TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256:
			case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
			case CipherSuite.TLS_RSA_WITH_AES_128_CCM:
			case CipherSuite.TLS_RSA_WITH_AES_128_CCM_8:
			case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
			case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
			case CipherSuite.TLS_RSA_WITH_AES_256_CCM:
			case CipherSuite.TLS_RSA_WITH_AES_256_CCM_8:
			case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384:
			case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256:
			case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256:
			case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256:
			case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384:
			case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
				return ProtocolVersion.TLSv12;

			default:
				return ProtocolVersion.SSLv3;
			}
		}

		public static bool isAEADCipherSuite(int ciphersuite)
		{
			return CipherType.aead == getCipherType(ciphersuite);
		}

		public static bool isBlockCipherSuite(int ciphersuite)
		{
			return CipherType.block == getCipherType(ciphersuite);
		}

		public static bool isStreamCipherSuite(int ciphersuite)
		{
			return CipherType.stream == getCipherType(ciphersuite);
		}

		public static bool isValidCipherSuiteForSignatureAlgorithms(int cipherSuite, Vector sigAlgs)
		{
			int keyExchangeAlgorithm;
			try
			{
				keyExchangeAlgorithm = getKeyExchangeAlgorithm(cipherSuite);
			}
			catch (IOException)
			{
				return true;
			}

			switch (keyExchangeAlgorithm)
			{
			case KeyExchangeAlgorithm.DH_anon:
			case KeyExchangeAlgorithm.DH_anon_EXPORT:
			case KeyExchangeAlgorithm.ECDH_anon:
				return sigAlgs.contains(Shorts.valueOf(SignatureAlgorithm.anonymous));

			case KeyExchangeAlgorithm.DHE_RSA:
			case KeyExchangeAlgorithm.DHE_RSA_EXPORT:
			case KeyExchangeAlgorithm.ECDHE_RSA:
			case KeyExchangeAlgorithm.SRP_RSA:
				return sigAlgs.contains(Shorts.valueOf(SignatureAlgorithm.rsa));

			case KeyExchangeAlgorithm.DHE_DSS:
			case KeyExchangeAlgorithm.DHE_DSS_EXPORT:
			case KeyExchangeAlgorithm.SRP_DSS:
				return sigAlgs.contains(Shorts.valueOf(SignatureAlgorithm.dsa));

			case KeyExchangeAlgorithm.ECDHE_ECDSA:
				return sigAlgs.contains(Shorts.valueOf(SignatureAlgorithm.ecdsa));

			default:
				return true;
			}
		}

		public static bool isValidCipherSuiteForVersion(int cipherSuite, ProtocolVersion serverVersion)
		{
			return getMinimumVersion(cipherSuite).isEqualOrEarlierVersionOf(serverVersion.getEquivalentTLSVersion());
		}

		public static Vector getUsableSignatureAlgorithms(Vector sigHashAlgs)
		{
			if (sigHashAlgs == null)
			{
				return getAllSignatureAlgorithms();
			}

			Vector v = new Vector(4);
			v.addElement(Shorts.valueOf(SignatureAlgorithm.anonymous));
			for (int i = 0; i < sigHashAlgs.size(); ++i)
			{
				SignatureAndHashAlgorithm sigHashAlg = (SignatureAndHashAlgorithm)sigHashAlgs.elementAt(i);
	//            if (sigHashAlg.getHash() >= MINIMUM_HASH_STRICT)
				{
					short? sigAlg = Shorts.valueOf(sigHashAlg.getSignature());
					if (!v.contains(sigAlg))
					{
						v.addElement(sigAlg);
					}
				}
			}
			return v;
		}
	}

}