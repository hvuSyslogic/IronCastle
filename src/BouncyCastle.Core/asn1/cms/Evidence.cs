using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{

	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5544">RFC 5544</a>:
	/// Binding Documents with Time-Stamps; Evidence object.
	/// <para>
	/// <pre>
	/// Evidence ::= CHOICE {
	///     tstEvidence    [0] TimeStampTokenEvidence,   -- see RFC 3161
	///     ersEvidence    [1] EvidenceRecord,           -- see RFC 4998
	///     otherEvidence  [2] OtherEvidence
	/// }
	/// </pre>
	/// </para>
	/// </summary>
	public class Evidence : ASN1Object, ASN1Choice
	{
		private TimeStampTokenEvidence tstEvidence;

		public Evidence(TimeStampTokenEvidence tstEvidence)
		{
			this.tstEvidence = tstEvidence;
		}

		private Evidence(ASN1TaggedObject tagged)
		{
			if (tagged.getTagNo() == 0)
			{
				this.tstEvidence = TimeStampTokenEvidence.getInstance(tagged, false);
			}
		}

		/// <summary>
		/// Return an Evidence object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> <seealso cref="Evidence"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1TaggedObject#getInstance(java.lang.Object) ASN1TaggedObject"/> input formats with Evidence data inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static Evidence getInstance(object obj)
		{
			if (obj == null || obj is Evidence)
			{
				return (Evidence)obj;
			}
			else if (obj is ASN1TaggedObject)
			{
				return new Evidence(ASN1TaggedObject.getInstance(obj));
			}

			throw new IllegalArgumentException("unknown object in getInstance");
		}

		public virtual TimeStampTokenEvidence getTstEvidence()
		{
			return tstEvidence;
		}

		public override ASN1Primitive toASN1Primitive()
		{
		   if (tstEvidence != null)
		   {
			   return new DERTaggedObject(false, 0, tstEvidence);
		   }

		   return null;
		}
	}

}