using System.IO;
using org.bouncycastle.asn1;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.agreement.kdf
{

	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using DERTaggedObject = org.bouncycastle.asn1.DERTaggedObject;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using KDF2BytesGenerator = org.bouncycastle.crypto.generators.KDF2BytesGenerator;
	using KDFParameters = org.bouncycastle.crypto.@params.KDFParameters;
	using Pack = org.bouncycastle.util.Pack;

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