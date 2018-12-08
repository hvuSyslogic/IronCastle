namespace org.bouncycastle.cert
{
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using ContentVerifierProvider = org.bouncycastle.@operator.ContentVerifierProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;

	public interface X509ContentVerifierProviderBuilder
	{
		ContentVerifierProvider build(SubjectPublicKeyInfo validatingKeyInfo);

		ContentVerifierProvider build(X509CertificateHolder validatingKeyInfo);
	}

}