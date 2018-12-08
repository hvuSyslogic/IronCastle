using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x509
{


	/// <summary>
	/// <code>NoticeReference</code> class, used in
	/// <code>CertificatePolicies</code> X509 V3 extensions
	/// (in policy qualifiers).
	/// 
	/// <pre>
	///  NoticeReference ::= SEQUENCE {
	///      organization     DisplayText,
	///      noticeNumbers    SEQUENCE OF INTEGER }
	/// 
	/// </pre> 
	/// </summary>
	/// <seealso cref= PolicyQualifierInfo </seealso>
	/// <seealso cref= PolicyInformation </seealso>
	public class NoticeReference : ASN1Object
	{
		private DisplayText organization;
		private ASN1Sequence noticeNumbers;

		private static ASN1EncodableVector convertVector(Vector numbers)
		{
			ASN1EncodableVector av = new ASN1EncodableVector();

			Enumeration it = numbers.elements();

			while (it.hasMoreElements())
			{
				object o = it.nextElement();
				ASN1Integer di;

				if (o is BigInteger)
				{
					di = new ASN1Integer((BigInteger)o);
				}
				else if (o is int?)
				{
					di = new ASN1Integer(((int?)o).Value);
				}
				else
				{
					throw new IllegalArgumentException();
				}

				av.add(di);
			}
			return av;
		}

	   /// <summary>
	   /// Creates a new <code>NoticeReference</code> instance.
	   /// </summary>
	   /// <param name="organization"> a <code>String</code> value </param>
	   /// <param name="numbers"> a <code>Vector</code> value </param>
	   public NoticeReference(string organization, Vector numbers) : this(organization, convertVector(numbers))
	   {
	   }

		/// <summary>
		/// Creates a new <code>NoticeReference</code> instance.
		/// </summary>
		/// <param name="organization"> a <code>String</code> value </param>
		/// <param name="noticeNumbers"> an <code>ASN1EncodableVector</code> value </param>
	   public NoticeReference(string organization, ASN1EncodableVector noticeNumbers) : this(new DisplayText(organization), noticeNumbers)
	   {
	   }

	   /// <summary>
	   /// Creates a new <code>NoticeReference</code> instance.
	   /// </summary>
	   /// <param name="organization"> displayText </param>
	   /// <param name="noticeNumbers"> an <code>ASN1EncodableVector</code> value </param>
	   public NoticeReference(DisplayText organization, ASN1EncodableVector noticeNumbers)
	   {
		   this.organization = organization;
		   this.noticeNumbers = new DERSequence(noticeNumbers);
	   }

	   /// <summary>
	   /// Creates a new <code>NoticeReference</code> instance.
	   /// <para>Useful for reconstructing a <code>NoticeReference</code>
	   /// instance from its encodable/encoded form. 
	   /// 
	   /// </para>
	   /// </summary>
	   /// <param name="as"> an <code>ASN1Sequence</code> value obtained from either
	   /// calling @{link toASN1Primitive()} for a <code>NoticeReference</code>
	   /// instance or from parsing it from a DER-encoded stream.  </param>
	   private NoticeReference(ASN1Sequence @as)
	   {
		   if (@as.size() != 2)
		   {
				throw new IllegalArgumentException("Bad sequence size: " + @as.size());
		   }

		   organization = DisplayText.getInstance(@as.getObjectAt(0));
		   noticeNumbers = ASN1Sequence.getInstance(@as.getObjectAt(1));
	   }

	   public static NoticeReference getInstance(object @as)
	   {
		  if (@as is NoticeReference)
		  {
			  return (NoticeReference)@as;
		  }
		  else if (@as != null)
		  {
			  return new NoticeReference(ASN1Sequence.getInstance(@as));
		  }

		  return null;
	   }

	   public virtual DisplayText getOrganization()
	   {
		   return organization;
	   }

	   public virtual ASN1Integer[] getNoticeNumbers()
	   {
		   ASN1Integer[] tmp = new ASN1Integer[noticeNumbers.size()];

		   for (int i = 0; i != noticeNumbers.size(); i++)
		   {
			   tmp[i] = ASN1Integer.getInstance(noticeNumbers.getObjectAt(i));
		   }

		   return tmp;
	   }

	   /// <summary>
	   /// Describe <code>toASN1Object</code> method here.
	   /// </summary>
	   /// <returns> a <code>ASN1Primitive</code> value </returns>
	   public override ASN1Primitive toASN1Primitive()
	   {
		  ASN1EncodableVector av = new ASN1EncodableVector();
		  av.add(organization);
		  av.add(noticeNumbers);
		  return new DERSequence(av);
	   }
	}

}