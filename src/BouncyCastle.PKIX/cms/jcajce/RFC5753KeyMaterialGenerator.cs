using org.bouncycastle.asn1;

namespace org.bouncycastle.cms.jcajce
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ECCCMSSharedInfo = org.bouncycastle.asn1.cms.ecc.ECCCMSSharedInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Pack = org.bouncycastle.util.Pack;

	public class RFC5753KeyMaterialGenerator : KeyMaterialGenerator
	{
		public virtual byte[] generateKDFMaterial(AlgorithmIdentifier keyAlgorithm, int keySize, byte[] userKeyMaterialParameters)
		{
			ECCCMSSharedInfo eccInfo = new ECCCMSSharedInfo(keyAlgorithm, userKeyMaterialParameters, Pack.intToBigEndian(keySize));

			try
			{
				return eccInfo.getEncoded(ASN1Encoding_Fields.DER);
			}
			catch (IOException e)
			{
				throw new IllegalStateException("Unable to create KDF material: " + e);
			}
		}
	}

}