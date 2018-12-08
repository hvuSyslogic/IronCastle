namespace org.bouncycastle.jcajce.provider.config
{

	using ECParameterSpec = org.bouncycastle.jce.spec.ECParameterSpec;

	public interface ProviderConfiguration
	{
		ECParameterSpec getEcImplicitlyCa();

		DHParameterSpec getDHDefaultParameters(int keySize);

		DSAParameterSpec getDSADefaultParameters(int keySize);

		Set getAcceptableNamedCurves();

		Map getAdditionalECParameters();
	}

}