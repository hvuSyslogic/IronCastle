using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.util
{
	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

	public class KeyUtil
	{
		public static byte[] getEncodedSubjectPublicKeyInfo(AlgorithmIdentifier algId, ASN1Encodable keyData)
		{
			try
			{
				return getEncodedSubjectPublicKeyInfo(new SubjectPublicKeyInfo(algId, keyData));
			}
			catch (Exception)
			{
				return null;
			}
		}

		public static byte[] getEncodedSubjectPublicKeyInfo(AlgorithmIdentifier algId, byte[] keyData)
		{
			try
			{
				return getEncodedSubjectPublicKeyInfo(new SubjectPublicKeyInfo(algId, keyData));
			}
			catch (Exception)
			{
				return null;
			}
		}

		public static byte[] getEncodedSubjectPublicKeyInfo(SubjectPublicKeyInfo info)
		{
			 try
			 {
				 return info.getEncoded(ASN1Encoding_Fields.DER);
			 }
			 catch (Exception)
			 {
				 return null;
			 }
		}

		public static byte[] getEncodedPrivateKeyInfo(AlgorithmIdentifier algId, ASN1Encodable privKey)
		{
			 try
			 {
				 PrivateKeyInfo info = new PrivateKeyInfo(algId, privKey.toASN1Primitive());

				 return getEncodedPrivateKeyInfo(info);
			 }
			 catch (Exception)
			 {
				 return null;
			 }
		}

		public static byte[] getEncodedPrivateKeyInfo(PrivateKeyInfo info)
		{
			 try
			 {
				 return info.getEncoded(ASN1Encoding_Fields.DER);
			 }
			 catch (Exception)
			 {
				 return null;
			 }
		}
	}

}