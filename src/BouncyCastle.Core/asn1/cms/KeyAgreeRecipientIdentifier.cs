using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{

	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652#section-6.2.2">RFC 5652</a>:
	/// Content encryption key delivery mechanisms.
	/// <para>
	/// <pre>
	/// KeyAgreeRecipientIdentifier ::= CHOICE {
	///     issuerAndSerialNumber IssuerAndSerialNumber,
	///     rKeyId [0] IMPLICIT RecipientKeyIdentifier }
	/// </pre>
	/// </para>
	/// </summary>
	public class KeyAgreeRecipientIdentifier : ASN1Object, ASN1Choice
	{
		private IssuerAndSerialNumber issuerSerial;
		private RecipientKeyIdentifier rKeyID;

		/// <summary>
		/// Return an KeyAgreeRecipientIdentifier object from a tagged object.
		/// </summary>
		/// <param name="obj"> the tagged object holding the object we want. </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///              tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the object held by the
		///          tagged object cannot be converted. </exception>
		public static KeyAgreeRecipientIdentifier getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		/// <summary>
		/// Return an KeyAgreeRecipientIdentifier object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> <seealso cref="KeyAgreeRecipientIdentifier"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats with IssuerAndSerialNumber structure inside
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1TaggedObject#getInstance(java.lang.Object) ASN1TaggedObject"/> with tag value 0: a KeyAgreeRecipientIdentifier data structure
		/// </ul>
		/// </para>
		/// <para>
		/// Note: no byte[] input!
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static KeyAgreeRecipientIdentifier getInstance(object obj)
		{
			if (obj == null || obj is KeyAgreeRecipientIdentifier)
			{
				return (KeyAgreeRecipientIdentifier)obj;
			}

			if (obj is ASN1Sequence)
			{
				return new KeyAgreeRecipientIdentifier(IssuerAndSerialNumber.getInstance(obj));
			}

			if (obj is ASN1TaggedObject && ((ASN1TaggedObject)obj).getTagNo() == 0)
			{
				return new KeyAgreeRecipientIdentifier(RecipientKeyIdentifier.getInstance((ASN1TaggedObject)obj, false));
			}

			throw new IllegalArgumentException("Invalid KeyAgreeRecipientIdentifier: " + obj.GetType().getName());
		}

		public KeyAgreeRecipientIdentifier(IssuerAndSerialNumber issuerSerial)
		{
			this.issuerSerial = issuerSerial;
			this.rKeyID = null;
		}

		public KeyAgreeRecipientIdentifier(RecipientKeyIdentifier rKeyID)
		{
			this.issuerSerial = null;
			this.rKeyID = rKeyID;
		}

		public virtual IssuerAndSerialNumber getIssuerAndSerialNumber()
		{
			return issuerSerial;
		}

		public virtual RecipientKeyIdentifier getRKeyID()
		{
			return rKeyID;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			if (issuerSerial != null)
			{
				return issuerSerial.toASN1Primitive();
			}

			return new DERTaggedObject(false, 0, rKeyID);
		}
	}

}