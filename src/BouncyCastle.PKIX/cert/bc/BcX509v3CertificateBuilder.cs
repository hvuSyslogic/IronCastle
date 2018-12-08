using System;

namespace org.bouncycastle.cert.bc
{

	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using SubjectPublicKeyInfoFactory = org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

	/// <summary>
	/// JCA helper class to allow BC lightweight objects to be used in the construction of a Version 3 certificate.
	/// </summary>
	public class BcX509v3CertificateBuilder : X509v3CertificateBuilder
	{
		/// <summary>
		/// Initialise the builder using a PublicKey.
		/// </summary>
		/// <param name="issuer"> X500Name representing the issuer of this certificate. </param>
		/// <param name="serial"> the serial number for the certificate. </param>
		/// <param name="notBefore"> date before which the certificate is not valid. </param>
		/// <param name="notAfter"> date after which the certificate is not valid. </param>
		/// <param name="subject"> X500Name representing the subject of this certificate. </param>
		/// <param name="publicKey"> the public key to be associated with the certificate. </param>
		public BcX509v3CertificateBuilder(X500Name issuer, BigInteger serial, DateTime notBefore, DateTime notAfter, X500Name subject, AsymmetricKeyParameter publicKey) : base(issuer, serial, notBefore, notAfter, subject, SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey))
		{
		}

		/// <summary>
		/// Initialise the builder using the subject from the passed in issuerCert as the issuer, as well as
		/// passing through and converting the other objects provided.
		/// </summary>
		/// <param name="issuerCert"> holder for certificate who's subject is the issuer of the certificate we are building. </param>
		/// <param name="serial"> the serial number for the certificate. </param>
		/// <param name="notBefore"> date before which the certificate is not valid. </param>
		/// <param name="notAfter"> date after which the certificate is not valid. </param>
		/// <param name="subject"> principal representing the subject of this certificate. </param>
		/// <param name="publicKey"> the public key to be associated with the certificate. </param>
		public BcX509v3CertificateBuilder(X509CertificateHolder issuerCert, BigInteger serial, DateTime notBefore, DateTime notAfter, X500Name subject, AsymmetricKeyParameter publicKey) : base(issuerCert.getSubject(), serial, notBefore, notAfter, subject, SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(publicKey))
		{
		}
	}

}