using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{

	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652#section-6.2.2">RFC 5652</a>:
	/// Content encryption key delivery mechanisms.
	/// <pre>
	/// RecipientEncryptedKey ::= SEQUENCE {
	///     rid KeyAgreeRecipientIdentifier,
	///     encryptedKey EncryptedKey
	/// }
	/// </pre>
	/// </summary>
	public class RecipientEncryptedKey : ASN1Object
	{
		private KeyAgreeRecipientIdentifier identifier;
		private ASN1OctetString encryptedKey;

		private RecipientEncryptedKey(ASN1Sequence seq)
		{
			identifier = KeyAgreeRecipientIdentifier.getInstance(seq.getObjectAt(0));
			encryptedKey = (ASN1OctetString)seq.getObjectAt(1);
		}

		/// <summary>
		/// Return an RecipientEncryptedKey object from a tagged object.
		/// </summary>
		/// <param name="obj"> the tagged object holding the object we want. </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///              tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the object held by the
		///          tagged object cannot be converted. </exception>
		public static RecipientEncryptedKey getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		/// <summary>
		/// Return a RecipientEncryptedKey object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="RecipientEncryptedKey"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats with RecipientEncryptedKey structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static RecipientEncryptedKey getInstance(object obj)
		{
			if (obj is RecipientEncryptedKey)
			{
				return (RecipientEncryptedKey)obj;
			}

			if (obj != null)
			{
				return new RecipientEncryptedKey(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public RecipientEncryptedKey(KeyAgreeRecipientIdentifier id, ASN1OctetString encryptedKey)
		{
			this.identifier = id;
			this.encryptedKey = encryptedKey;
		}

		public virtual KeyAgreeRecipientIdentifier getIdentifier()
		{
			return identifier;
		}

		public virtual ASN1OctetString getEncryptedKey()
		{
			return encryptedKey;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(identifier);
			v.add(encryptedKey);

			return new DERSequence(v);
		}
	}

}