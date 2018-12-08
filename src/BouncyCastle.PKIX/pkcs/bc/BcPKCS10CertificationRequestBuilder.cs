namespace org.bouncycastle.pkcs.bc
{

	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using SubjectPublicKeyInfoFactory = org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

	/// <summary>
	/// Extension of the PKCS#10 builder to support AsymmetricKey objects.
	/// </summary>
	public class BcPKCS10CertificationRequestBuilder : PKCS10CertificationRequestBuilder
	{
		/// <summary>
		/// Create a PKCS#10 builder for the passed in subject and JCA public key.
		/// </summary>
		/// <param name="subject"> an X500Name containing the subject associated with the request we are building. </param>
		/// <param name="publicKey"> a JCA public key that is to be associated with the request we are building. </param>
		/// <exception cref="IOException"> if there is a problem encoding the public key. </exception>
		public BcPKCS10CertificationRequestBuilder(X500Name subject, AsymmetricKeyParameter publicKey) : base(subject, SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey))
		{
		}
	}

}