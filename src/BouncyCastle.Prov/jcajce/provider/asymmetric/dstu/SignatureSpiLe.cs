using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.dstu
{

	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;

	public class SignatureSpiLe : SignatureSpi
	{
		public virtual void reverseBytes(byte[] bytes)
		{
			byte tmp;

			for (int i = 0; i < bytes.Length / 2; i++)
			{
				tmp = bytes[i];
				bytes[i] = bytes[bytes.Length - 1 - i];
				bytes[bytes.Length - 1 - i] = tmp;
			}
		}

		public override byte[] engineSign()
		{
			byte[] signature = ASN1OctetString.getInstance(base.engineSign()).getOctets();
			reverseBytes(signature);
			try
			{
				return (new DEROctetString(signature)).getEncoded();
			}
			catch (Exception e)
			{
				throw new SignatureException(e.ToString());
			}
		}

		public override bool engineVerify(byte[] sigBytes)
		{
			byte[] bytes = null;

			try
			{
				bytes = ((ASN1OctetString)ASN1OctetString.fromByteArray(sigBytes)).getOctets();
			}
			catch (IOException)
			{
				throw new SignatureException("error decoding signature bytes.");
			}

			reverseBytes(bytes);

			try
			{
				return base.engineVerify((new DEROctetString(bytes)).getEncoded());
			}
			catch (SignatureException e)
			{
				throw e;
			}
			catch (Exception e)
			{
				throw new SignatureException(e.ToString());
			}
		}
	}

}