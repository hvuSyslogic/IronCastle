namespace org.bouncycastle.pkcs.jcajce
{

	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

	/// <summary>
	/// Extension of the PKCS#10 builder to support PublicKey and X500Principal objects.
	/// </summary>
	public class JcaPKCS10CertificationRequestBuilder : PKCS10CertificationRequestBuilder
	{
		/// <summary>
		/// Create a PKCS#10 builder for the passed in subject and JCA public key.
		/// </summary>
		/// <param name="subject"> an X500Name containing the subject associated with the request we are building. </param>
		/// <param name="publicKey"> a JCA public key that is to be associated with the request we are building. </param>
		public JcaPKCS10CertificationRequestBuilder(X500Name subject, PublicKey publicKey) : base(subject, SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()))
		{
		}

		/// <summary>
		/// Create a PKCS#10 builder for the passed in subject and JCA public key.
		/// </summary>
		/// <param name="subject"> an X500Principal containing the subject associated with the request we are building. </param>
		/// <param name="publicKey"> a JCA public key that is to be associated with the request we are building. </param>
		public JcaPKCS10CertificationRequestBuilder(X500Principal subject, PublicKey publicKey) : base(X500Name.getInstance(subject.getEncoded()), SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()))
		{
		}
	}

}