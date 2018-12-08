namespace org.bouncycastle.openpgp.@operator
{

	public interface PGPContentVerifierBuilderProvider
	{
		PGPContentVerifierBuilder get(int keyAlgorithm, int hashAlgorithm);
	}

}