using System.IO;
using org.bouncycastle.Port;

namespace org.bouncycastle.asn1.eac
{

	using Arrays = org.bouncycastle.util.Arrays;


	/// <summary>
	/// an iso7816Certificate structure.
	/// <pre>
	///  Certificate ::= SEQUENCE {
	///      CertificateBody         Iso7816CertificateBody,
	///      signature               DER Application specific
	///  }
	/// </pre>
	/// </summary>
	public class CVCertificate : ASN1Object
	{
		private CertificateBody certificateBody;
		private byte[] signature;
		private int valid;
		private static int bodyValid = 0x01;
		private static int signValid = 0x02;

		/// <summary>
		/// Sets the values of the certificate (body and signature).
		/// </summary>
		/// <param name="appSpe"> is a ASN1ApplicationSpecific object containing body and signature. </param>
		/// <exception cref="IOException"> if tags or value are incorrect. </exception>
		private void setPrivateData(ASN1ApplicationSpecific appSpe)
		{
			valid = 0;
			if (appSpe.getApplicationTag() == EACTags.CARDHOLDER_CERTIFICATE)
			{
				ASN1InputStream content = new ASN1InputStream(appSpe.getContents());
				ASN1Primitive tmpObj;
				while ((tmpObj = content.readObject()) != null)
				{
					ASN1ApplicationSpecific aSpe;
					if (tmpObj is ASN1ApplicationSpecific)
					{
						aSpe = (ASN1ApplicationSpecific)tmpObj;
						switch (aSpe.getApplicationTag())
						{
						case EACTags.CERTIFICATE_CONTENT_TEMPLATE:
							certificateBody = CertificateBody.getInstance(aSpe);
							valid |= bodyValid;
							break;
						case EACTags.STATIC_INTERNAL_AUTHENTIFICATION_ONE_STEP:
							signature = aSpe.getContents();
							valid |= signValid;
							break;
						default:
							throw new IOException("Invalid tag, not an Iso7816CertificateStructure :" + aSpe.getApplicationTag());
						}
					}
					else
					{
						throw new IOException("Invalid Object, not an Iso7816CertificateStructure");
					}
				}
				content.close();
			}
			else
			{
				throw new IOException("not a CARDHOLDER_CERTIFICATE :" + appSpe.getApplicationTag());
			}

			if (valid != (signValid | bodyValid))
			{
				throw new IOException("invalid CARDHOLDER_CERTIFICATE :" + appSpe.getApplicationTag());
			}
		}

		/// <summary>
		/// Create an iso7816Certificate structure from an ASN1InputStream.
		/// </summary>
		/// <param name="aIS"> the byte stream to parse. </param>
		/// <exception cref="IOException"> if there is a problem parsing the data. </exception>
		public CVCertificate(ASN1InputStream aIS)
		{
			initFrom(aIS);
		}

		private void initFrom(ASN1InputStream aIS)
		{
			ASN1Primitive obj;
			while ((obj = aIS.readObject()) != null)
			{
				if (obj is ASN1ApplicationSpecific)
				{
					setPrivateData((ASN1ApplicationSpecific)obj);
				}
				else
				{
					throw new IOException("Invalid Input Stream for creating an Iso7816CertificateStructure");
				}
			}
		}

		/// <summary>
		/// Create an iso7816Certificate structure from a ASN1ApplicationSpecific.
		/// </summary>
		/// <param name="appSpe"> the ASN1ApplicationSpecific object. </param>
		/// <returns> the Iso7816CertificateStructure represented by the ASN1ApplicationSpecific object. </returns>
		/// <exception cref="IOException"> if there is a problem parsing the data. </exception>
		private CVCertificate(ASN1ApplicationSpecific appSpe)
		{
			setPrivateData(appSpe);
		}

		/// <summary>
		/// Create an iso7816Certificate structure from a body and its signature.
		/// </summary>
		/// <param name="body"> the Iso7816CertificateBody object containing the body. </param>
		/// <param name="signature">   the byte array containing the signature </param>
		/// <exception cref="IOException"> if there is a problem parsing the data. </exception>
		public CVCertificate(CertificateBody body, byte[] signature)
		{
			certificateBody = body;
			this.signature = Arrays.clone(signature);
			// patch remi
			valid |= bodyValid;
			valid |= signValid;
		}

		/// <summary>
		/// Create an iso7816Certificate structure from an object.
		/// </summary>
		/// <param name="obj"> the Object to extract the certificate from. </param>
		/// <returns> the Iso7816CertificateStructure represented by the byte stream. </returns>
		public static CVCertificate getInstance(object obj)
		{
			if (obj is CVCertificate)
			{
				return (CVCertificate)obj;
			}
			else if (obj != null)
			{
				try
				{
					return new CVCertificate(ASN1ApplicationSpecific.getInstance(obj));
				}
				catch (IOException e)
				{
					throw new ASN1ParsingException("unable to parse data: " + e.Message, e);
				}
			}

			return null;
		}

		/// <summary>
		/// Gives the signature of the whole body. Type of signature is given in
		/// the Iso7816CertificateBody.Iso7816PublicKey.ASN1ObjectIdentifier
		/// </summary>
		/// <returns> the signature of the body. </returns>
		public virtual byte[] getSignature()
		{
			return Arrays.clone(signature);
		}

		/// <summary>
		/// Gives the body of the certificate.
		/// </summary>
		/// <returns> the body. </returns>
		public virtual CertificateBody getBody()
		{
			return certificateBody;
		}

		/// <seealso cref= org.bouncycastle.asn1.ASN1Object#toASN1Primitive() </seealso>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(certificateBody);

			try
			{
				v.add(new DERApplicationSpecific(false, EACTags.STATIC_INTERNAL_AUTHENTIFICATION_ONE_STEP, new DEROctetString(signature)));
			}
			catch (IOException)
			{
				throw new IllegalStateException("unable to convert signature!");
			}

			return new DERApplicationSpecific(EACTags.CARDHOLDER_CERTIFICATE, v);
		}

		/// <returns> the Holder authorization and role (CVCA, DV, IS). </returns>
		public virtual ASN1ObjectIdentifier getHolderAuthorization()
		{
			CertificateHolderAuthorization cha = certificateBody.getCertificateHolderAuthorization();
			return cha.getOid();
		}

		/// <returns> the date of the certificate generation </returns>
		public virtual PackedDate getEffectiveDate()
		{
			return certificateBody.getCertificateEffectiveDate();
		}


		/// <returns> the type of certificate (request or profile)
		///         value is either Iso7816CertificateBody.profileType
		///         or Iso7816CertificateBody.requestType. Any other value
		///         is not valid. </returns>
		public virtual int getCertificateType()
		{
			return this.certificateBody.getCertificateType();
		}

		/// <returns> the date of the certificate generation </returns>
		public virtual PackedDate getExpirationDate()
		{
			return certificateBody.getCertificateExpirationDate();
		}


		/// <summary>
		/// return a bits field coded on one byte. For signification of the
		/// several bit see Iso7816CertificateHolderAuthorization
		/// </summary>
		/// <returns> role and access rigth </returns>
		/// <exception cref="IOException"> </exception>
		/// <seealso cref= CertificateHolderAuthorization </seealso>
		public virtual int getRole()
		{
			CertificateHolderAuthorization cha = certificateBody.getCertificateHolderAuthorization();
			return cha.getAccessRights();
		}

		/// <returns> the Authority Reference field of the certificate </returns>
		/// <exception cref="IOException"> </exception>
		public virtual CertificationAuthorityReference getAuthorityReference()
		{
			return certificateBody.getCertificationAuthorityReference();
		}

		/// <returns> the Holder Reference Field of the certificate </returns>
		/// <exception cref="IOException"> </exception>
		public virtual CertificateHolderReference getHolderReference()
		{
			return certificateBody.getCertificateHolderReference();
		}

		/// <returns> the bits corresponding to the role intented for the certificate
		///         See Iso7816CertificateHolderAuthorization static int for values </returns>
		/// <exception cref="IOException"> </exception>
		public virtual int getHolderAuthorizationRole()
		{
			int rights = certificateBody.getCertificateHolderAuthorization().getAccessRights();
			return rights & 0xC0;
		}

		/// <returns> the bits corresponding the authorizations contained in the certificate
		///         See Iso7816CertificateHolderAuthorization static int for values </returns>
		/// <exception cref="IOException"> </exception>
		public virtual Flags getHolderAuthorizationRights()
		{
			return new Flags(certificateBody.getCertificateHolderAuthorization().getAccessRights() & 0x1F);
		}
	}

}