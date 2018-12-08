using System.IO;
using org.bouncycastle.asn1;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.eac
{



	/// <summary>
	/// an Iso7816CertificateBody structure.
	/// <pre>
	///  CertificateBody ::= SEQUENCE {
	///      // version of the certificate format. Must be 0 (version 1)
	///      CertificateProfileIdentifer         ASN1ApplicationSpecific,
	///      //uniquely identifies the issuinng CA's signature key pair
	///      // contains the iso3166-1 alpha2 encoded country code, the
	///      // name of issuer and the sequence number of the key pair.
	///      CertificationAuthorityReference        ASN1ApplicationSpecific,
	///      // stores the encoded public key
	///      PublicKey                            Iso7816PublicKey,
	///      //associates the public key contained in the certificate with a unique name
	///      // contains the iso3166-1 alpha2 encoded country code, the
	///      // name of the holder and the sequence number of the key pair.
	///      certificateHolderReference            ASN1ApplicationSpecific,
	///      // Encodes the role of the holder (i.e. CVCA, DV, IS) and assigns read/write
	///      // access rights to data groups storing sensitive data
	///      certificateHolderAuthorization        Iso7816CertificateHolderAuthorization,
	///      // the date of the certificate generation
	///      CertificateEffectiveDate            ASN1ApplicationSpecific,
	///      // the date after wich the certificate expires
	///      certificateExpirationDate            ASN1ApplicationSpecific
	///  }
	/// </pre>
	/// </summary>
	public class CertificateBody : ASN1Object
	{
		internal ASN1InputStream seq;
		private ASN1ApplicationSpecific certificateProfileIdentifier; // version of the certificate format. Must be 0 (version 1)
		private ASN1ApplicationSpecific certificationAuthorityReference; //uniquely identifies the issuinng CA's signature key pair
		private PublicKeyDataObject publicKey; // stores the encoded public key
		private ASN1ApplicationSpecific certificateHolderReference; //associates the public key contained in the certificate with a unique name
		private CertificateHolderAuthorization certificateHolderAuthorization; // Encodes the role of the holder (i.e. CVCA, DV, IS) and assigns read/write access rights to data groups storing sensitive data
		private ASN1ApplicationSpecific certificateEffectiveDate; // the date of the certificate generation
		private ASN1ApplicationSpecific certificateExpirationDate; // the date after wich the certificate expires
		private int certificateType = 0; // bit field of initialized data. This will tell us if the data are valid.
		private const int CPI = 0x01; //certificate Profile Identifier
		private const int CAR = 0x02; //certification Authority Reference
		private const int PK = 0x04; //public Key
		private const int CHR = 0x08; //certificate Holder Reference
		private const int CHA = 0x10; //certificate Holder Authorization
		private const int CEfD = 0x20; //certificate Effective Date
		private const int CExD = 0x40; //certificate Expiration Date

		public const int profileType = 0x7f; //Profile type Certificate
		public const int requestType = 0x0D; // Request type Certificate

		private void setIso7816CertificateBody(ASN1ApplicationSpecific appSpe)
		{
			byte[] content;
			if (appSpe.getApplicationTag() == EACTags.CERTIFICATE_CONTENT_TEMPLATE)
			{
				content = appSpe.getContents();
			}
			else
			{
				throw new IOException("Bad tag : not an iso7816 CERTIFICATE_CONTENT_TEMPLATE");
			}
			ASN1InputStream aIS = new ASN1InputStream(content);
			ASN1Primitive obj;
			while ((obj = aIS.readObject()) != null)
			{
				ASN1ApplicationSpecific aSpe;

				if (obj is ASN1ApplicationSpecific)
				{
					aSpe = (ASN1ApplicationSpecific)obj;
				}
				else
				{
					throw new IOException("Not a valid iso7816 content : not a ASN1ApplicationSpecific Object :" + EACTags.encodeTag(appSpe) + obj.GetType());
				}
				switch (aSpe.getApplicationTag())
				{
				case EACTags.INTERCHANGE_PROFILE:
					setCertificateProfileIdentifier(aSpe);
					break;
				case EACTags.ISSUER_IDENTIFICATION_NUMBER:
					setCertificationAuthorityReference(aSpe);
					break;
				case EACTags.CARDHOLDER_PUBLIC_KEY_TEMPLATE:
					setPublicKey(PublicKeyDataObject.getInstance(aSpe.getObject(BERTags_Fields.SEQUENCE)));
					break;
				case EACTags.CARDHOLDER_NAME:
					setCertificateHolderReference(aSpe);
					break;
				case EACTags.CERTIFICATE_HOLDER_AUTHORIZATION_TEMPLATE:
					setCertificateHolderAuthorization(new CertificateHolderAuthorization(aSpe));
					break;
				case EACTags.APPLICATION_EFFECTIVE_DATE:
					setCertificateEffectiveDate(aSpe);
					break;
				case EACTags.APPLICATION_EXPIRATION_DATE:
					setCertificateExpirationDate(aSpe);
					break;
				default:
					certificateType = 0;
					throw new IOException("Not a valid iso7816 ASN1ApplicationSpecific tag " + aSpe.getApplicationTag());
				}
			}
			aIS.close();
		}

		/// <summary>
		/// builds an Iso7816CertificateBody by settings each parameters.
		/// </summary>
		/// <param name="certificateProfileIdentifier"> </param>
		/// <param name="certificationAuthorityReference">
		/// </param>
		/// <param name="publicKey"> </param>
		/// <param name="certificateHolderReference"> </param>
		/// <param name="certificateHolderAuthorization"> </param>
		/// <param name="certificateEffectiveDate"> </param>
		/// <param name="certificateExpirationDate"> </param>
		public CertificateBody(ASN1ApplicationSpecific certificateProfileIdentifier, CertificationAuthorityReference certificationAuthorityReference, PublicKeyDataObject publicKey, CertificateHolderReference certificateHolderReference, CertificateHolderAuthorization certificateHolderAuthorization, PackedDate certificateEffectiveDate, PackedDate certificateExpirationDate)
		{
			setCertificateProfileIdentifier(certificateProfileIdentifier);
			setCertificationAuthorityReference(new DERApplicationSpecific(EACTags.ISSUER_IDENTIFICATION_NUMBER, certificationAuthorityReference.getEncoded()));
			setPublicKey(publicKey);
			setCertificateHolderReference(new DERApplicationSpecific(EACTags.CARDHOLDER_NAME, certificateHolderReference.getEncoded()));
			setCertificateHolderAuthorization(certificateHolderAuthorization);
			try
			{
				setCertificateEffectiveDate(new DERApplicationSpecific(false, EACTags.APPLICATION_EFFECTIVE_DATE, new DEROctetString(certificateEffectiveDate.getEncoding())));
				setCertificateExpirationDate(new DERApplicationSpecific(false, EACTags.APPLICATION_EXPIRATION_DATE, new DEROctetString(certificateExpirationDate.getEncoding())));
			}
			catch (IOException e)
			{
				throw new IllegalArgumentException("unable to encode dates: " + e.Message);
			}
		}

		/// <summary>
		/// builds an Iso7816CertificateBody with an ASN1InputStream.
		/// </summary>
		/// <param name="obj"> ASN1ApplicationSpecific containing the whole body. </param>
		/// <exception cref="IOException"> if the body is not valid. </exception>
		private CertificateBody(ASN1ApplicationSpecific obj)
		{
			setIso7816CertificateBody(obj);
		}

		/// <summary>
		/// create a profile type Iso7816CertificateBody.
		/// </summary>
		/// <returns> return the "profile" type certificate body. </returns>
		/// <exception cref="IOException"> if the ASN1ApplicationSpecific cannot be created. </exception>
		private ASN1Primitive profileToASN1Object()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(certificateProfileIdentifier);
			v.add(certificationAuthorityReference);
			v.add(new DERApplicationSpecific(false, EACTags.CARDHOLDER_PUBLIC_KEY_TEMPLATE, publicKey));
			v.add(certificateHolderReference);
			v.add(certificateHolderAuthorization);
			v.add(certificateEffectiveDate);
			v.add(certificateExpirationDate);
			return new DERApplicationSpecific(EACTags.CERTIFICATE_CONTENT_TEMPLATE, v);
		}

		private void setCertificateProfileIdentifier(ASN1ApplicationSpecific certificateProfileIdentifier)
		{
			if (certificateProfileIdentifier.getApplicationTag() == EACTags.INTERCHANGE_PROFILE)
			{
				this.certificateProfileIdentifier = certificateProfileIdentifier;
				certificateType |= CPI;
			}
			else
			{
				throw new IllegalArgumentException("Not an Iso7816Tags.INTERCHANGE_PROFILE tag :" + EACTags.encodeTag(certificateProfileIdentifier));
			}
		}

		private void setCertificateHolderReference(ASN1ApplicationSpecific certificateHolderReference)
		{
			if (certificateHolderReference.getApplicationTag() == EACTags.CARDHOLDER_NAME)
			{
				this.certificateHolderReference = certificateHolderReference;
				certificateType |= CHR;
			}
			else
			{
				throw new IllegalArgumentException("Not an Iso7816Tags.CARDHOLDER_NAME tag");
			}
		}

		/// <summary>
		/// set the CertificationAuthorityReference.
		/// </summary>
		/// <param name="certificationAuthorityReference">
		///         the ASN1ApplicationSpecific containing the CertificationAuthorityReference. </param>
		/// <exception cref="IllegalArgumentException"> if the ASN1ApplicationSpecific is not valid. </exception>
		private void setCertificationAuthorityReference(ASN1ApplicationSpecific certificationAuthorityReference)
		{
			if (certificationAuthorityReference.getApplicationTag() == EACTags.ISSUER_IDENTIFICATION_NUMBER)
			{
				this.certificationAuthorityReference = certificationAuthorityReference;
				certificateType |= CAR;
			}
			else
			{
				throw new IllegalArgumentException("Not an Iso7816Tags.ISSUER_IDENTIFICATION_NUMBER tag");
			}
		}

		/// <summary>
		/// set the public Key
		/// </summary>
		/// <param name="publicKey"> : the ASN1ApplicationSpecific containing the public key </param>
		/// <exception cref="IOException"> </exception>
		private void setPublicKey(PublicKeyDataObject publicKey)
		{
			this.publicKey = PublicKeyDataObject.getInstance(publicKey);
			this.certificateType |= PK;
		}

		/// <summary>
		/// create a request type Iso7816CertificateBody.
		/// </summary>
		/// <returns> return the "request" type certificate body. </returns>
		/// <exception cref="IOException"> if the ASN1ApplicationSpecific cannot be created. </exception>
		private ASN1Primitive requestToASN1Object()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(certificateProfileIdentifier);
			v.add(new DERApplicationSpecific(false, EACTags.CARDHOLDER_PUBLIC_KEY_TEMPLATE, publicKey));
			v.add(certificateHolderReference);
			return new DERApplicationSpecific(EACTags.CERTIFICATE_CONTENT_TEMPLATE, v);
		}

		/// <summary>
		/// create a "request" or "profile" type Iso7816CertificateBody according to the variables sets.
		/// </summary>
		/// <returns> return the ASN1Primitive representing the "request" or "profile" type certificate body. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			try
			{
				if (certificateType == profileType)
				{
					return profileToASN1Object();
				}
				if (certificateType == requestType)
				{
					return requestToASN1Object();
				}
			}
			catch (IOException)
			{
				return null;
			}
			return null;
		}

		/// <summary>
		/// gives the type of the certificate (value should be profileType or requestType if all data are set).
		/// </summary>
		/// <returns> the int representing the data already set. </returns>
		public virtual int getCertificateType()
		{
			return certificateType;
		}

		/// <summary>
		/// Gives an instance of Iso7816CertificateBody taken from Object obj
		/// </summary>
		/// <param name="obj"> is the Object to extract the certificate body from. </param>
		/// <returns> the Iso7816CertificateBody taken from Object obj. </returns>
		/// <exception cref="IOException"> if object is not valid. </exception>
		public static CertificateBody getInstance(object obj)
		{
			if (obj is CertificateBody)
			{
				return (CertificateBody)obj;
			}
			else if (obj != null)
			{
				return new CertificateBody(ASN1ApplicationSpecific.getInstance(obj));
			}

			return null;
		}

		/// <returns> the date of the certificate generation </returns>
		public virtual PackedDate getCertificateEffectiveDate()
		{
			if ((this.certificateType & CertificateBody.CEfD) == CertificateBody.CEfD)
			{
				return new PackedDate(certificateEffectiveDate.getContents());
			}
			return null;
		}

		/// <summary>
		/// set the date of the certificate generation
		/// </summary>
		/// <param name="ced"> ASN1ApplicationSpecific containing the date of the certificate generation </param>
		/// <exception cref="IllegalArgumentException"> if the tag is not Iso7816Tags.APPLICATION_EFFECTIVE_DATE </exception>
		private void setCertificateEffectiveDate(ASN1ApplicationSpecific ced)
		{
			if (ced.getApplicationTag() == EACTags.APPLICATION_EFFECTIVE_DATE)
			{
				this.certificateEffectiveDate = ced;
				certificateType |= CEfD;
			}
			else
			{
				throw new IllegalArgumentException("Not an Iso7816Tags.APPLICATION_EFFECTIVE_DATE tag :" + EACTags.encodeTag(ced));
			}
		}

		/// <returns> the date after wich the certificate expires </returns>
		public virtual PackedDate getCertificateExpirationDate()
		{
			if ((this.certificateType & CertificateBody.CExD) == CertificateBody.CExD)
			{
				return new PackedDate(certificateExpirationDate.getContents());
			}
			throw new IOException("certificate Expiration Date not set");
		}

		/// <summary>
		/// set the date after wich the certificate expires
		/// </summary>
		/// <param name="ced"> ASN1ApplicationSpecific containing the date after wich the certificate expires </param>
		/// <exception cref="IllegalArgumentException"> if the tag is not Iso7816Tags.APPLICATION_EXPIRATION_DATE </exception>
		private void setCertificateExpirationDate(ASN1ApplicationSpecific ced)
		{
			if (ced.getApplicationTag() == EACTags.APPLICATION_EXPIRATION_DATE)
			{
				this.certificateExpirationDate = ced;
				certificateType |= CExD;
			}
			else
			{
				throw new IllegalArgumentException("Not an Iso7816Tags.APPLICATION_EXPIRATION_DATE tag");
			}
		}

		/// <summary>
		/// the Iso7816CertificateHolderAuthorization encodes the role of the holder
		/// (i.e. CVCA, DV, IS) and assigns read/write access rights to data groups
		/// storing sensitive data. This functions returns the Certificate Holder
		/// Authorization
		/// </summary>
		/// <returns> the Iso7816CertificateHolderAuthorization </returns>
		public virtual CertificateHolderAuthorization getCertificateHolderAuthorization()
		{
			if ((this.certificateType & CertificateBody.CHA) == CertificateBody.CHA)
			{
				return certificateHolderAuthorization;
			}
			throw new IOException("Certificate Holder Authorisation not set");
		}

		/// <summary>
		/// set the CertificateHolderAuthorization
		/// </summary>
		/// <param name="cha"> the Certificate Holder Authorization </param>
		private void setCertificateHolderAuthorization(CertificateHolderAuthorization cha)
		{
			this.certificateHolderAuthorization = cha;
			certificateType |= CHA;
		}

		/// <summary>
		/// certificateHolderReference : associates the public key contained in the certificate with a unique name
		/// </summary>
		/// <returns> the certificateHolderReference. </returns>
		public virtual CertificateHolderReference getCertificateHolderReference()
		{
			return new CertificateHolderReference(certificateHolderReference.getContents());
		}

		/// <summary>
		/// CertificateProfileIdentifier : version of the certificate format. Must be 0 (version 1)
		/// </summary>
		/// <returns> the CertificateProfileIdentifier </returns>
		public virtual ASN1ApplicationSpecific getCertificateProfileIdentifier()
		{
			return certificateProfileIdentifier;
		}

		/// <summary>
		/// get the certificationAuthorityReference
		/// certificationAuthorityReference : uniquely identifies the issuinng CA's signature key pair
		/// </summary>
		/// <returns> the certificationAuthorityReference </returns>
		public virtual CertificationAuthorityReference getCertificationAuthorityReference()
		{
			if ((this.certificateType & CertificateBody.CAR) == CertificateBody.CAR)
			{
				return new CertificationAuthorityReference(certificationAuthorityReference.getContents());
			}
			throw new IOException("Certification authority reference not set");
		}

		/// <returns> the PublicKey </returns>
		public virtual PublicKeyDataObject getPublicKey()
		{
			return publicKey;
		}
	}

}