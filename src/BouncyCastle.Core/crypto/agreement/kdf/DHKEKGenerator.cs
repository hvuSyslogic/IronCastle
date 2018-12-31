using System.IO;
using org.bouncycastle.asn1;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.agreement.kdf
{

							
	/// <summary>
	/// RFC 2631 Diffie-hellman KEK derivation function.
	/// </summary>
	public class DHKEKGenerator : DerivationFunction
	{
		private readonly Digest digest;

		private ASN1ObjectIdentifier algorithm;
		private int keySize;
		private byte[] z;
		private byte[] partyAInfo;

		public DHKEKGenerator(Digest digest)
		{
			this.digest = digest;
		}

		public virtual void init(DerivationParameters param)
		{
			DHKDFParameters @params = (DHKDFParameters)param;

			this.algorithm = @params.getAlgorithm();
			this.keySize = @params.getKeySize();
			this.z = @params.getZ();
			this.partyAInfo = @params.getExtraInfo();
		}

		public virtual Digest getDigest()
		{
			return digest;
		}

		public virtual int generateBytes(byte[] @out, int outOff, int len)
		{
			if ((@out.Length - len) < outOff)
			{
				throw new OutputLengthException("output buffer too small");
			}

			long oBytes = len;
			int outLen = digest.getDigestSize();

			//
			// this is at odds with the standard implementation, the
			// maximum value should be hBits * (2^32 - 1) where hBits
			// is the digest output size in bits. We can't have an
			// array with a long index at the moment...
			//
			if (oBytes > ((2L << 32) - 1))
			{
				throw new IllegalArgumentException("Output length too large");
			}

			int cThreshold = (int)((oBytes + outLen - 1) / outLen);

			byte[] dig = new byte[digest.getDigestSize()];

			int counter = 1;

			for (int i = 0; i < cThreshold; i++)
			{
				digest.update(z, 0, z.Length);

				// OtherInfo
				ASN1EncodableVector v1 = new ASN1EncodableVector();
				// KeySpecificInfo
				ASN1EncodableVector v2 = new ASN1EncodableVector();

				v2.add(algorithm);
				v2.add(new DEROctetString(Pack.intToBigEndian(counter)));

				v1.add(new DERSequence(v2));

				if (partyAInfo != null)
				{
					v1.add(new DERTaggedObject(true, 0, new DEROctetString(partyAInfo)));
				}

				v1.add(new DERTaggedObject(true, 2, new DEROctetString(Pack.intToBigEndian(keySize))));

				try
				{
					byte[] other = (new DERSequence(v1)).getEncoded(ASN1Encoding_Fields.DER);

					digest.update(other, 0, other.Length);
				}
				catch (IOException e)
				{
					throw new IllegalArgumentException("unable to encode parameter info: " + e.Message);
				}

				digest.doFinal(dig, 0);

				if (len > outLen)
				{
					JavaSystem.arraycopy(dig, 0, @out, outOff, outLen);
					outOff += outLen;
					len -= outLen;
				}
				else
				{
					JavaSystem.arraycopy(dig, 0, @out, outOff, len);
				}

				counter++;
			}

			digest.reset();

			return (int)oBytes;
		}
	}

}