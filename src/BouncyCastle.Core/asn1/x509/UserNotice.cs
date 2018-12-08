using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509
{

	/// <summary>
	/// <code>UserNotice</code> class, used in
	/// <code>CertificatePolicies</code> X509 extensions (in policy
	/// qualifiers).
	/// <pre>
	/// UserNotice ::= SEQUENCE {
	///      noticeRef        NoticeReference OPTIONAL,
	///      explicitText     DisplayText OPTIONAL}
	/// 
	/// </pre>
	/// </summary>
	/// <seealso cref= PolicyQualifierId </seealso>
	/// <seealso cref= PolicyInformation </seealso>
	public class UserNotice : ASN1Object
	{
		private readonly NoticeReference noticeRef;
		private readonly DisplayText explicitText;

		/// <summary>
		/// Creates a new <code>UserNotice</code> instance.
		/// </summary>
		/// <param name="noticeRef"> a <code>NoticeReference</code> value </param>
		/// <param name="explicitText"> a <code>DisplayText</code> value </param>
		public UserNotice(NoticeReference noticeRef, DisplayText explicitText)
		{
			this.noticeRef = noticeRef;
			this.explicitText = explicitText;
		}

		/// <summary>
		/// Creates a new <code>UserNotice</code> instance.
		/// </summary>
		/// <param name="noticeRef"> a <code>NoticeReference</code> value </param>
		/// <param name="str"> the explicitText field as a String.  </param>
		public UserNotice(NoticeReference noticeRef, string str) : this(noticeRef, new DisplayText(str))
		{
		}

		/// <summary>
		/// Creates a new <code>UserNotice</code> instance.
		/// <para>Useful from reconstructing a <code>UserNotice</code> instance
		/// from its encodable/encoded form. 
		/// 
		/// </para>
		/// </summary>
		/// <param name="as"> an <code>ASN1Sequence</code> value obtained from either
		/// calling @{link toASN1Primitive()} for a <code>UserNotice</code>
		/// instance or from parsing it from a DER-encoded stream.  </param>
		private UserNotice(ASN1Sequence @as)
		{
		   if (@as.size() == 2)
		   {
			   noticeRef = NoticeReference.getInstance(@as.getObjectAt(0));
			   explicitText = DisplayText.getInstance(@as.getObjectAt(1));
		   }
		   else if (@as.size() == 1)
		   {
			   if (@as.getObjectAt(0).toASN1Primitive() is ASN1Sequence)
			   {
				   noticeRef = NoticeReference.getInstance(@as.getObjectAt(0));
				   explicitText = null;
			   }
			   else
			   {
				   explicitText = DisplayText.getInstance(@as.getObjectAt(0));
				   noticeRef = null;
			   }
		   }
		   else if (@as.size() == 0) // neither field set!
		   {
			   noticeRef = null;
			   explicitText = null;
		   }
		   else
		   {
			   throw new IllegalArgumentException("Bad sequence size: " + @as.size());
		   }
		}

		public static UserNotice getInstance(object obj)
		{
			if (obj is UserNotice)
			{
				return (UserNotice)obj;
			}

			if (obj != null)
			{
				return new UserNotice(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual NoticeReference getNoticeRef()
		{
			return noticeRef;
		}

		public virtual DisplayText getExplicitText()
		{
			return explicitText;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector av = new ASN1EncodableVector();

			if (noticeRef != null)
			{
				av.add(noticeRef);
			}

			if (explicitText != null)
			{
				av.add(explicitText);
			}

			return new DERSequence(av);
		}
	}

}