namespace org.bouncycastle.jce.interfaces
{
	using GOST3410PublicKeyParameterSetSpec = org.bouncycastle.jce.spec.GOST3410PublicKeyParameterSetSpec;

	public interface GOST3410Params
	{

		string getPublicKeyParamSetOID();

		string getDigestParamSetOID();

		string getEncryptionParamSetOID();

		GOST3410PublicKeyParameterSetSpec getPublicKeyParameters();
	}

}