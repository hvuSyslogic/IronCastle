namespace org.bouncycastle.jce
{

	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using TBSCertList = org.bouncycastle.asn1.x509.TBSCertList;
	using TBSCertificateStructure = org.bouncycastle.asn1.x509.TBSCertificateStructure;
	using X509Name = org.bouncycastle.asn1.x509.X509Name;

	/// <summary>
	/// a utility class that will extract X509Principal objects from X.509 certificates.
	/// <para>
	/// Use this in preference to trying to recreate a principal from a String, not all
	/// DNs are what they should be, so it's best to leave them encoded where they
	/// can be.
	/// </para>
	/// </summary>
	public class PrincipalUtil
	{
		/// <summary>
		/// return the issuer of the given cert as an X509PrincipalObject.
		/// </summary>
		public static X509Principal getIssuerX509Principal(X509Certificate cert)
		{
			try
			{
				TBSCertificateStructure tbsCert = TBSCertificateStructure.getInstance(ASN1Primitive.fromByteArray(cert.getTBSCertificate()));

				return new X509Principal(X509Name.getInstance(tbsCert.getIssuer()));
			}
			catch (IOException e)
			{
				throw new CertificateEncodingException(e.ToString());
			}
		}

		/// <summary>
		/// return the subject of the given cert as an X509PrincipalObject.
		/// </summary>
		public static X509Principal getSubjectX509Principal(X509Certificate cert)
		{
			try
			{
				TBSCertificateStructure tbsCert = TBSCertificateStructure.getInstance(ASN1Primitive.fromByteArray(cert.getTBSCertificate()));
				return new X509Principal(X509Name.getInstance(tbsCert.getSubject()));
			}
			catch (IOException e)
			{
				throw new CertificateEncodingException(e.ToString());
			}
		}

		/// <summary>
		/// return the issuer of the given CRL as an X509PrincipalObject.
		/// </summary>
		public static X509Principal getIssuerX509Principal(X509CRL crl)
		{
			try
			{
				TBSCertList tbsCertList = TBSCertList.getInstance(ASN1Primitive.fromByteArray(crl.getTBSCertList()));

				return new X509Principal(X509Name.getInstance(tbsCertList.getIssuer()));
			}
			catch (IOException e)
			{
				throw new CRLException(e.ToString());
			}
		}
	}

}