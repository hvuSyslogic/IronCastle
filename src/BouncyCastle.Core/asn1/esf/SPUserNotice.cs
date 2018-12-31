using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.esf
{

		
	public class SPUserNotice : ASN1Object
	{
		private NoticeReference noticeRef;
		private DisplayText explicitText;

		public static SPUserNotice getInstance(object obj)
		{
			if (obj is SPUserNotice)
			{
				return (SPUserNotice)obj;
			}
			else if (obj != null)
			{
				return new SPUserNotice(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private SPUserNotice(ASN1Sequence seq)
		{
			Enumeration e = seq.getObjects();
			while (e.hasMoreElements())
			{
				ASN1Encodable @object = (ASN1Encodable)e.nextElement();
				if (@object is DisplayText || @object is ASN1String)
				{
					explicitText = DisplayText.getInstance(@object);
				}
				else if (@object is NoticeReference || @object is ASN1Sequence)
				{
					noticeRef = NoticeReference.getInstance(@object);
				}
				else
				{
					throw new IllegalArgumentException("Invalid element in 'SPUserNotice': " + @object.GetType().getName());
				}
			}
		}

		public SPUserNotice(NoticeReference noticeRef, DisplayText explicitText)
		{
			this.noticeRef = noticeRef;
			this.explicitText = explicitText;
		}

		public virtual NoticeReference getNoticeRef()
		{
			return noticeRef;
		}

		public virtual DisplayText getExplicitText()
		{
			return explicitText;
		}

		/// <summary>
		/// <pre>
		/// SPUserNotice ::= SEQUENCE {
		///     noticeRef NoticeReference OPTIONAL,
		///     explicitText DisplayText OPTIONAL }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			if (noticeRef != null)
			{
				v.add(noticeRef);
			}

			if (explicitText != null)
			{
				v.add(explicitText);
			}

			return new DERSequence(v);
		}
	}

}