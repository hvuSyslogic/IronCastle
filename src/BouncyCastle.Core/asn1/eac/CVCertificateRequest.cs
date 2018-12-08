using System.IO;
using org.bouncycastle.asn1;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.eac
{

	using Arrays = org.bouncycastle.util.Arrays;

	public class CVCertificateRequest : ASN1Object
	{
		private readonly ASN1ApplicationSpecific original;

		private CertificateBody certificateBody;

		private byte[] innerSignature = null;
		private byte[] outerSignature = null;

		private const int bodyValid = 0x01;
		private const int signValid = 0x02;

		private CVCertificateRequest(ASN1ApplicationSpecific request)
		{
			this.original = request;

			if (request.isConstructed() && request.getApplicationTag() == EACTags.AUTHENTIFICATION_DATA)
			{
				ASN1Sequence seq = ASN1Sequence.getInstance(request.getObject(BERTags_Fields.SEQUENCE));

				initCertBody(ASN1ApplicationSpecific.getInstance(seq.getObjectAt(0)));

				outerSignature = ASN1ApplicationSpecific.getInstance(seq.getObjectAt(seq.size() - 1)).getContents();
			}
			else
			{
				initCertBody(request);
			}
		}

		private void initCertBody(ASN1ApplicationSpecific request)
		{
			if (request.getApplicationTag() == EACTags.CARDHOLDER_CERTIFICATE)
			{
				int valid = 0;
				ASN1Sequence seq = ASN1Sequence.getInstance(request.getObject(BERTags_Fields.SEQUENCE));
				for (Enumeration en = seq.getObjects(); en.hasMoreElements();)
				{
					ASN1ApplicationSpecific obj = ASN1ApplicationSpecific.getInstance(en.nextElement());
					switch (obj.getApplicationTag())
					{
					case EACTags.CERTIFICATE_CONTENT_TEMPLATE:
						certificateBody = CertificateBody.getInstance(obj);
						valid |= bodyValid;
						break;
					case EACTags.STATIC_INTERNAL_AUTHENTIFICATION_ONE_STEP:
						innerSignature = obj.getContents();
						valid |= signValid;
						break;
					default:
						throw new IOException("Invalid tag, not an CV Certificate Request element:" + obj.getApplicationTag());
					}
				}
				if ((valid & (bodyValid | signValid)) == 0)
				{
					throw new IOException("Invalid CARDHOLDER_CERTIFICATE in request:" + request.getApplicationTag());
				}
			}
			else
			{
				throw new IOException("not a CARDHOLDER_CERTIFICATE in request:" + request.getApplicationTag());
			}
		}

		public static CVCertificateRequest getInstance(object obj)
		{
			if (obj is CVCertificateRequest)
			{
				return (CVCertificateRequest)obj;
			}
			else if (obj != null)
			{
				try
				{
					return new CVCertificateRequest(ASN1ApplicationSpecific.getInstance(obj));
				}
				catch (IOException e)
				{
					throw new ASN1ParsingException("unable to parse data: " + e.Message, e);
				}
			}

			return null;
		}

		/// <summary>
		/// Returns the body of the certificate template
		/// </summary>
		/// <returns> the body. </returns>
		public virtual CertificateBody getCertificateBody()
		{
			return certificateBody;
		}

		/// <summary>
		/// Return the public key data object carried in the request </summary>
		/// <returns>  the public key </returns>
		public virtual PublicKeyDataObject getPublicKey()
		{
			return certificateBody.getPublicKey();
		}

		public virtual byte[] getInnerSignature()
		{
			return Arrays.clone(innerSignature);
		}

		public virtual byte[] getOuterSignature()
		{
			return Arrays.clone(outerSignature);
		}

		public virtual bool hasOuterSignature()
		{
			return outerSignature != null;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			if (original != null)
			{
				return original;
			}
			else
			{
				ASN1EncodableVector v = new ASN1EncodableVector();

				v.add(certificateBody);

				try
				{
					v.add(new DERApplicationSpecific(false, EACTags.STATIC_INTERNAL_AUTHENTIFICATION_ONE_STEP, new DEROctetString(innerSignature)));
				}
				catch (IOException)
				{
					throw new IllegalStateException("unable to convert signature!");
				}

				return new DERApplicationSpecific(EACTags.CARDHOLDER_CERTIFICATE, v);
			}
		}
	}

}