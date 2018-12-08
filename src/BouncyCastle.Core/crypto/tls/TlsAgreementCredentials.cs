namespace org.bouncycastle.crypto.tls
{

	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;

	public interface TlsAgreementCredentials : TlsCredentials
	{
		byte[] generateAgreement(AsymmetricKeyParameter peerPublicKey);
	}

}