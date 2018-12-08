using System;

namespace org.bouncycastle.x509.extension
{

	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using AuthorityKeyIdentifier = org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using GeneralNames = org.bouncycastle.asn1.x509.GeneralNames;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X509Extension = org.bouncycastle.asn1.x509.X509Extension;
	using PrincipalUtil = org.bouncycastle.jce.PrincipalUtil;

	/// <summary>
	/// A high level authority key identifier. </summary>
	/// @deprecated use JcaX509ExtensionUtils and AuthorityKeyIdentifier.getInstance() 
	public class AuthorityKeyIdentifierStructure : AuthorityKeyIdentifier
	{
		/// <summary>
		/// Constructor which will take the byte[] returned from getExtensionValue()
		/// </summary>
		/// <param name="encodedValue"> a DER octet encoded string with the extension structure in it. </param>
		/// <exception cref="IOException"> on parsing errors. </exception>
		public AuthorityKeyIdentifierStructure(byte[] encodedValue) : base((ASN1Sequence)X509ExtensionUtil.fromExtensionValue(encodedValue))
		{
		}

		/// <summary>
		/// Constructor which will take an extension
		/// </summary>
		/// <param name="extension"> a X509Extension object containing an AuthorityKeyIdentifier. </param>
		/// @deprecated use constructor that takes Extension 
		public AuthorityKeyIdentifierStructure(X509Extension extension) : base((ASN1Sequence)extension.getParsedValue())
		{
		}

		/// <summary>
		/// Constructor which will take an extension
		/// </summary>
		/// <param name="extension"> a X509Extension object containing an AuthorityKeyIdentifier. </param>
		public AuthorityKeyIdentifierStructure(Extension extension) : base((ASN1Sequence)extension.getParsedValue())
		{
		}

		private static ASN1Sequence fromCertificate(X509Certificate certificate)
		{
			try
			{
				if (certificate.getVersion() != 3)
				{
					GeneralName genName = new GeneralName(PrincipalUtil.getIssuerX509Principal(certificate));
					SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(certificate.getPublicKey().getEncoded());

					return (ASN1Sequence)(new AuthorityKeyIdentifier(info, new GeneralNames(genName), certificate.getSerialNumber())).toASN1Primitive();
				}
				else
				{
					GeneralName genName = new GeneralName(PrincipalUtil.getIssuerX509Principal(certificate));

					byte[] ext = certificate.getExtensionValue(Extension.subjectKeyIdentifier.getId());

					if (ext != null)
					{
						ASN1OctetString str = (ASN1OctetString)X509ExtensionUtil.fromExtensionValue(ext);

						return (ASN1Sequence)(new AuthorityKeyIdentifier(str.getOctets(), new GeneralNames(genName), certificate.getSerialNumber())).toASN1Primitive();
					}
					else
					{
						SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(certificate.getPublicKey().getEncoded());

						return (ASN1Sequence)(new AuthorityKeyIdentifier(info, new GeneralNames(genName), certificate.getSerialNumber())).toASN1Primitive();
					}
				}
			}
			catch (Exception e)
			{
				throw new CertificateParsingException("Exception extracting certificate details: " + e.ToString());
			}
		}

		private static ASN1Sequence fromKey(PublicKey pubKey)
		{
			try
			{
				SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(pubKey.getEncoded());

				return (ASN1Sequence)(new AuthorityKeyIdentifier(info)).toASN1Primitive();
			}
			catch (Exception e)
			{
				throw new InvalidKeyException("can't process key: " + e);
			}
		}

		/// <summary>
		/// Create an AuthorityKeyIdentifier using the passed in certificate's public
		/// key, issuer and serial number.
		/// </summary>
		/// <param name="certificate"> the certificate providing the information. </param>
		/// <exception cref="CertificateParsingException"> if there is a problem processing the certificate </exception>
		public AuthorityKeyIdentifierStructure(X509Certificate certificate) : base(fromCertificate(certificate))
		{
		}

		/// <summary>
		/// Create an AuthorityKeyIdentifier using just the hash of the 
		/// public key.
		/// </summary>
		/// <param name="pubKey"> the key to generate the hash from. </param>
		/// <exception cref="InvalidKeyException"> if there is a problem using the key. </exception>
		public AuthorityKeyIdentifierStructure(PublicKey pubKey) : base(fromKey(pubKey))
		{
		}
	}

}