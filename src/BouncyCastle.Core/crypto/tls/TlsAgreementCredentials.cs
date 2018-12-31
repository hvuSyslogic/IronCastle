using org.bouncycastle.crypto.@params;

namespace org.bouncycastle.crypto.tls
{

	
	public interface TlsAgreementCredentials : TlsCredentials
	{
		byte[] generateAgreement(AsymmetricKeyParameter peerPublicKey);
	}

}