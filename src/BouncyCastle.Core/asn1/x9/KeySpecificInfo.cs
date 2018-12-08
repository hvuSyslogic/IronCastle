using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x9
{


	/// <summary>
	/// ASN.1 def for Diffie-Hellman key exchange KeySpecificInfo structure. See
	/// RFC 2631, or X9.42, for further details.
	/// <pre>
	///  KeySpecificInfo ::= SEQUENCE {
	///      algorithm OBJECT IDENTIFIER,
	///      counter OCTET STRING SIZE (4..4)
	///  }
	/// </pre>
	/// </summary>
	public class KeySpecificInfo : ASN1Object
	{
		private ASN1ObjectIdentifier algorithm;
		private ASN1OctetString counter;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="algorithm">  algorithm identifier for the CEK. </param>
		/// <param name="counter"> initial counter value for key derivation. </param>
		public KeySpecificInfo(ASN1ObjectIdentifier algorithm, ASN1OctetString counter)
		{
			this.algorithm = algorithm;
			this.counter = counter;
		}

		/// <summary>
		/// Return a KeySpecificInfo object from the passed in object.
		/// </summary>
		/// <param name="obj"> an object for conversion or a byte[]. </param>
		/// <returns> a KeySpecificInfo </returns>
		public static KeySpecificInfo getInstance(object obj)
		{
			if (obj is KeySpecificInfo)
			{
				return (KeySpecificInfo)obj;
			}
			else if (obj != null)
			{
				return new KeySpecificInfo(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private KeySpecificInfo(ASN1Sequence seq)
		{
			Enumeration e = seq.getObjects();

			algorithm = (ASN1ObjectIdentifier)e.nextElement();
			counter = (ASN1OctetString)e.nextElement();
		}

		/// <summary>
		/// The object identifier for the CEK wrapping algorithm.
		/// </summary>
		/// <returns> CEK wrapping algorithm OID. </returns>
		public virtual ASN1ObjectIdentifier getAlgorithm()
		{
			return algorithm;
		}

		/// <summary>
		/// The initial counter value for key derivation.
		/// </summary>
		/// <returns> initial counter value as a 4 byte octet string (big endian). </returns>
		public virtual ASN1OctetString getCounter()
		{
			return counter;
		}

		/// <summary>
		/// Return an ASN.1 primitive representation of this object.
		/// </summary>
		/// <returns> a DERSequence containing the KeySpecificInfo values. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(algorithm);
			v.add(counter);

			return new DERSequence(v);
		}
	}

}