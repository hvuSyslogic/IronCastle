namespace org.bouncycastle.bcpg
{

	using EmbeddedSignature = org.bouncycastle.bcpg.sig.EmbeddedSignature;
	using Exportable = org.bouncycastle.bcpg.sig.Exportable;
	using Features = org.bouncycastle.bcpg.sig.Features;
	using IssuerKeyID = org.bouncycastle.bcpg.sig.IssuerKeyID;
	using KeyExpirationTime = org.bouncycastle.bcpg.sig.KeyExpirationTime;
	using KeyFlags = org.bouncycastle.bcpg.sig.KeyFlags;
	using NotationData = org.bouncycastle.bcpg.sig.NotationData;
	using PreferredAlgorithms = org.bouncycastle.bcpg.sig.PreferredAlgorithms;
	using PrimaryUserID = org.bouncycastle.bcpg.sig.PrimaryUserID;
	using Revocable = org.bouncycastle.bcpg.sig.Revocable;
	using RevocationReason = org.bouncycastle.bcpg.sig.RevocationReason;
	using SignatureCreationTime = org.bouncycastle.bcpg.sig.SignatureCreationTime;
	using SignatureExpirationTime = org.bouncycastle.bcpg.sig.SignatureExpirationTime;
	using SignatureTarget = org.bouncycastle.bcpg.sig.SignatureTarget;
	using SignerUserID = org.bouncycastle.bcpg.sig.SignerUserID;
	using TrustSignature = org.bouncycastle.bcpg.sig.TrustSignature;
	using Arrays = org.bouncycastle.util.Arrays;
	using Streams = org.bouncycastle.util.io.Streams;

	/// <summary>
	/// reader for signature sub-packets
	/// </summary>
	public class SignatureSubpacketInputStream : InputStream, SignatureSubpacketTags
	{
		internal InputStream @in;

		public SignatureSubpacketInputStream(InputStream @in)
		{
			this.@in = @in;
		}

		public virtual int available()
		{
			return @in.available();
		}

		public virtual int read()
		{
			return @in.read();
		}

		public virtual SignatureSubpacket readPacket()
		{
			int l = this.read();
			int bodyLen = 0;

			if (l < 0)
			{
				return null;
			}

			bool isLongLength = false;

			if (l < 192)
			{
				bodyLen = l;
			}
			else if (l <= 223)
			{
				bodyLen = ((l - 192) << 8) + (@in.read()) + 192;
			}
			else if (l == 255)
			{
				isLongLength = true;
				bodyLen = (@in.read() << 24) | (@in.read() << 16) | (@in.read() << 8) | @in.read();
			}
			else
			{
				throw new IOException("unexpected length header");
			}

			int tag = @in.read();

			if (tag < 0)
			{
				throw new EOFException("unexpected EOF reading signature sub packet");
			}

			byte[] data = new byte[bodyLen - 1];

			//
			// this may seem a bit strange but it turns out some applications miscode the length
			// in fixed length fields, so we check the length we do get, only throwing an exception if
			// we really cannot continue
			//
			int bytesRead = Streams.readFully(@in, data);

			bool isCritical = ((tag & 0x80) != 0);
			int type = tag & 0x7f;

			if (bytesRead != data.Length)
			{
				switch (type)
				{
				case SignatureSubpacketTags_Fields.CREATION_TIME:
					data = checkData(data, 4, bytesRead, "Signature Creation Time");
					break;
				case SignatureSubpacketTags_Fields.ISSUER_KEY_ID:
					data = checkData(data, 8, bytesRead, "Issuer");
					break;
				case SignatureSubpacketTags_Fields.KEY_EXPIRE_TIME:
					data = checkData(data, 4, bytesRead, "Signature Key Expiration Time");
					break;
				case SignatureSubpacketTags_Fields.EXPIRE_TIME:
					data = checkData(data, 4, bytesRead, "Signature Expiration Time");
					break;
				default:
					throw new EOFException("truncated subpacket data.");
				}
			}

			switch (type)
			{
			case SignatureSubpacketTags_Fields.CREATION_TIME:
				return new SignatureCreationTime(isCritical, isLongLength, data);
			case SignatureSubpacketTags_Fields.EMBEDDED_SIGNATURE:
				return new EmbeddedSignature(isCritical, isLongLength, data);
			case SignatureSubpacketTags_Fields.KEY_EXPIRE_TIME:
				return new KeyExpirationTime(isCritical, isLongLength, data);
			case SignatureSubpacketTags_Fields.EXPIRE_TIME:
				return new SignatureExpirationTime(isCritical, isLongLength, data);
			case SignatureSubpacketTags_Fields.REVOCABLE:
				return new Revocable(isCritical, isLongLength, data);
			case SignatureSubpacketTags_Fields.EXPORTABLE:
				return new Exportable(isCritical, isLongLength, data);
			case SignatureSubpacketTags_Fields.FEATURES:
				return new Features(isCritical, isLongLength, data);
			case SignatureSubpacketTags_Fields.ISSUER_KEY_ID:
				return new IssuerKeyID(isCritical, isLongLength, data);
			case SignatureSubpacketTags_Fields.TRUST_SIG:
				return new TrustSignature(isCritical, isLongLength, data);
			case SignatureSubpacketTags_Fields.PREFERRED_COMP_ALGS:
			case SignatureSubpacketTags_Fields.PREFERRED_HASH_ALGS:
			case SignatureSubpacketTags_Fields.PREFERRED_SYM_ALGS:
				return new PreferredAlgorithms(type, isCritical, isLongLength, data);
			case SignatureSubpacketTags_Fields.KEY_FLAGS:
				return new KeyFlags(isCritical, isLongLength, data);
			case SignatureSubpacketTags_Fields.PRIMARY_USER_ID:
				return new PrimaryUserID(isCritical, isLongLength, data);
			case SignatureSubpacketTags_Fields.SIGNER_USER_ID:
				return new SignerUserID(isCritical, isLongLength, data);
			case SignatureSubpacketTags_Fields.NOTATION_DATA:
				return new NotationData(isCritical, isLongLength, data);
			case SignatureSubpacketTags_Fields.REVOCATION_REASON:
				return new RevocationReason(isCritical, isLongLength, data);
			case SignatureSubpacketTags_Fields.SIGNATURE_TARGET:
				return new SignatureTarget(isCritical, isLongLength, data);
			}

			return new SignatureSubpacket(type, isCritical, isLongLength, data);
		}

		private byte[] checkData(byte[] data, int expected, int bytesRead, string name)
		{
			if (bytesRead != expected)
			{
				throw new EOFException("truncated " + name + " subpacket data.");
			}

			return Arrays.copyOfRange(data, 0, expected);
		}
	}

}