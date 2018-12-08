namespace org.bouncycastle.openpgp.@operator
{

	public interface PGPContentSignerBuilder
	{
//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public PGPContentSigner build(final int signatureType, final org.bouncycastle.openpgp.PGPPrivateKey privateKey) throws org.bouncycastle.openpgp.PGPException;
		PGPContentSigner build(int signatureType, PGPPrivateKey privateKey);
	}

}