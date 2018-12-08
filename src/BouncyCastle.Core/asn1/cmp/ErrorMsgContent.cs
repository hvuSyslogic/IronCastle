using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.cmp
{


	public class ErrorMsgContent : ASN1Object
	{
		private PKIStatusInfo pkiStatusInfo;
		private ASN1Integer errorCode;
		private PKIFreeText errorDetails;

		private ErrorMsgContent(ASN1Sequence seq)
		{
			Enumeration en = seq.getObjects();

			pkiStatusInfo = PKIStatusInfo.getInstance(en.nextElement());

			while (en.hasMoreElements())
			{
				object o = en.nextElement();

				if (o is ASN1Integer)
				{
					errorCode = ASN1Integer.getInstance(o);
				}
				else
				{
					errorDetails = PKIFreeText.getInstance(o);
				}
			}
		}

		public static ErrorMsgContent getInstance(object o)
		{
			if (o is ErrorMsgContent)
			{
				return (ErrorMsgContent)o;
			}

			if (o != null)
			{
				return new ErrorMsgContent(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public ErrorMsgContent(PKIStatusInfo pkiStatusInfo) : this(pkiStatusInfo, null, null)
		{
		}

		public ErrorMsgContent(PKIStatusInfo pkiStatusInfo, ASN1Integer errorCode, PKIFreeText errorDetails)
		{
			if (pkiStatusInfo == null)
			{
				throw new IllegalArgumentException("'pkiStatusInfo' cannot be null");
			}

			this.pkiStatusInfo = pkiStatusInfo;
			this.errorCode = errorCode;
			this.errorDetails = errorDetails;
		}

		public virtual PKIStatusInfo getPKIStatusInfo()
		{
			return pkiStatusInfo;
		}

		public virtual ASN1Integer getErrorCode()
		{
			return errorCode;
		}

		public virtual PKIFreeText getErrorDetails()
		{
			return errorDetails;
		}

		/// <summary>
		/// <pre>
		/// ErrorMsgContent ::= SEQUENCE {
		///                        pKIStatusInfo          PKIStatusInfo,
		///                        errorCode              INTEGER           OPTIONAL,
		///                        -- implementation-specific error codes
		///                        errorDetails           PKIFreeText       OPTIONAL
		///                        -- implementation-specific error details
		/// }
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(pkiStatusInfo);
			addOptional(v, errorCode);
			addOptional(v, errorDetails);

			return new DERSequence(v);
		}

		private void addOptional(ASN1EncodableVector v, ASN1Encodable obj)
		{
			if (obj != null)
			{
				v.add(obj);
			}
		}
	}

}