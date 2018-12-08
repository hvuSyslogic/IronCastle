using org.bouncycastle.crypto.@params;

namespace org.bouncycastle.crypto.tls
{
	public abstract class AbstractTlsAgreementCredentials : AbstractTlsCredentials, TlsAgreementCredentials
	{
		public override abstract Certificate getCertificate();
		public abstract byte[] generateAgreement(AsymmetricKeyParameter peerPublicKey);
	}

}