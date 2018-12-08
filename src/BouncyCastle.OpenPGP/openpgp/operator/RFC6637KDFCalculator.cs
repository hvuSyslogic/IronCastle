using org.bouncycastle.bcpg;

namespace org.bouncycastle.openpgp.@operator
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using PublicKeyAlgorithmTags = org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
	using SymmetricKeyAlgorithmTags = org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;
	using Hex = org.bouncycastle.util.encoders.Hex;

	/// <summary>
	/// Calculator for the EC based KDF algorithm described in RFC 6637 </summary>
	/// @deprecated this class is no longer required and will be removed. 
	public class RFC6637KDFCalculator
	{
		// "Anonymous Sender    ", which is the octet sequence
		private static readonly byte[] ANONYMOUS_SENDER = Hex.decode("416E6F6E796D6F75732053656E64657220202020");

		private readonly PGPDigestCalculator digCalc;
		private readonly int keyAlgorithm;

		public RFC6637KDFCalculator(PGPDigestCalculator digCalc, int keyAlgorithm)
		{
			this.digCalc = digCalc;
			this.keyAlgorithm = keyAlgorithm;
		}

		public virtual byte[] createKey(ASN1ObjectIdentifier curveOID, ECPoint s, byte[] recipientFingerPrint)
		{
			try
			{
				// RFC 6637 - Section 8
				// curve_OID_len = (byte)len(curve_OID);
				// Param = curve_OID_len || curve_OID || public_key_alg_ID || 03
				// || 01 || KDF_hash_ID || KEK_alg_ID for AESKeyWrap || "Anonymous
				// Sender    " || recipient_fingerprint;
				// Z_len = the key size for the KEK_alg_ID used with AESKeyWrap
				// Compute Z = KDF( S, Z_len, Param );
				ByteArrayOutputStream pOut = new ByteArrayOutputStream();

				byte[] encOid = curveOID.getEncoded();

				pOut.write(encOid, 1, encOid.Length - 1);
				pOut.write(PublicKeyAlgorithmTags_Fields.ECDH);
				pOut.write(0x03);
				pOut.write(0x01);
				pOut.write(digCalc.getAlgorithm());
				pOut.write(keyAlgorithm);
				pOut.write(ANONYMOUS_SENDER);
				pOut.write(recipientFingerPrint);

				return KDF(digCalc, s, getKeyLen(keyAlgorithm), pOut.toByteArray());
			}
			catch (IOException e)
			{
				throw new PGPException("Exception performing KDF: " + e.Message, e);
			}
		}

		// RFC 6637 - Section 7
		//   Implements KDF( X, oBits, Param );
		//   Input: point X = (x,y)
		//   oBits - the desired size of output
		//   hBits - the size of output of hash function Hash
		//   Param - octets representing the parameters
		//   Assumes that oBits <= hBits
		//   Convert the point X to the octet string, see section 6:
		//   ZB' = 04 || x || y
		//   and extract the x portion from ZB'
		//         ZB = x;
		//         MB = Hash ( 00 || 00 || 00 || 01 || ZB || Param );
		//   return oBits leftmost bits of MB.
		private static byte[] KDF(PGPDigestCalculator digCalc, ECPoint s, int keyLen, byte[] param)
		{
			byte[] ZB = s.getXCoord().getEncoded();

			OutputStream dOut = digCalc.getOutputStream();

			dOut.write(0x00);
			dOut.write(0x00);
			dOut.write(0x00);
			dOut.write(0x01);
			dOut.write(ZB);
			dOut.write(param);

			byte[] digest = digCalc.getDigest();

			byte[] key = new byte[keyLen];

			JavaSystem.arraycopy(digest, 0, key, 0, key.Length);

			return key;
		}

		private static int getKeyLen(int algID)
		{
			switch (algID)
			{
			case SymmetricKeyAlgorithmTags_Fields.AES_128:
				return 16;
			case SymmetricKeyAlgorithmTags_Fields.AES_192:
				return 24;
			case SymmetricKeyAlgorithmTags_Fields.AES_256:
				return 32;
			default:
				throw new PGPException("unknown symmetric algorithm ID: " + algID);
			}
		}
	}

}