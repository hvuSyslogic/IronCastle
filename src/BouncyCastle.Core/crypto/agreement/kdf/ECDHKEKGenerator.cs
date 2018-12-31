using System.IO;
using org.bouncycastle.asn1;
using org.bouncycastle.asn1.x509;
using org.bouncycastle.crypto.generators;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.agreement.kdf
{

											
	/// <summary>
	/// X9.63 based key derivation function for ECDH CMS.
	/// </summary>
	public class ECDHKEKGenerator : DigestDerivationFunction
	{
		private DigestDerivationFunction kdf;

		private ASN1ObjectIdentifier algorithm;
		private int keySize;
		private byte[] z;

		public ECDHKEKGenerator(Digest digest)
		{
			this.kdf = new KDF2BytesGenerator(digest);
		}

		public virtual void init(DerivationParameters param)
		{
			DHKDFParameters @params = (DHKDFParameters)param;

			this.algorithm = @params.getAlgorithm();
			this.keySize = @params.getKeySize();
			this.z = @params.getZ();
		}

		public virtual Digest getDigest()
		{
			return kdf.getDigest();
		}

		public virtual int generateBytes(byte[] @out, int outOff, int len)
		{
			if (outOff + len > @out.Length)
			{
				throw new DataLengthException("output buffer too small");
			}

			// TODO Create an ASN.1 class for this (RFC3278)
			// ECC-CMS-SharedInfo
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(new AlgorithmIdentifier(algorithm, DERNull.INSTANCE));
			v.add(new DERTaggedObject(true, 2, new DEROctetString(Pack.intToBigEndian(keySize))));

			try
			{
				kdf.init(new KDFParameters(z, (new DERSequence(v)).getEncoded(ASN1Encoding_Fields.DER)));
			}
			catch (IOException e)
			{
				throw new IllegalArgumentException("unable to initialise kdf: " + e.Message);
			}

			return kdf.generateBytes(@out, outOff, len);
		}
	}

}