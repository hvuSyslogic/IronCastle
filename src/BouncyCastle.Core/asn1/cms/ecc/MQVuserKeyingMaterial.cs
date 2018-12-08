using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms.ecc
{

	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5753">RFC 5753/3278</a>: MQVuserKeyingMaterial object.
	/// <pre>
	/// MQVuserKeyingMaterial ::= SEQUENCE {
	///   ephemeralPublicKey OriginatorPublicKey,
	///   addedukm [0] EXPLICIT UserKeyingMaterial OPTIONAL  }
	/// </pre>
	/// </summary>
	public class MQVuserKeyingMaterial : ASN1Object
	{
		private OriginatorPublicKey ephemeralPublicKey;
		private ASN1OctetString addedukm;

		public MQVuserKeyingMaterial(OriginatorPublicKey ephemeralPublicKey, ASN1OctetString addedukm)
		{
			if (ephemeralPublicKey == null)
			{
				throw new IllegalArgumentException("Ephemeral public key cannot be null");
			}

			this.ephemeralPublicKey = ephemeralPublicKey;
			this.addedukm = addedukm;
		}

		private MQVuserKeyingMaterial(ASN1Sequence seq)
		{
			if (seq.size() != 1 && seq.size() != 2)
			{
				throw new IllegalArgumentException("Sequence has incorrect number of elements");
			}

			this.ephemeralPublicKey = OriginatorPublicKey.getInstance(seq.getObjectAt(0));

			if (seq.size() > 1)
			{
				this.addedukm = ASN1OctetString.getInstance((ASN1TaggedObject)seq.getObjectAt(1), true);
			}
		}

		/// <summary>
		/// Return an MQVuserKeyingMaterial object from a tagged object.
		/// </summary>
		/// <param name="obj">      the tagged object holding the object we want. </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///                 tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the object held by the
		///                                  tagged object cannot be converted. </exception>
		public static MQVuserKeyingMaterial getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		/// <summary>
		/// Return an MQVuserKeyingMaterial object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="MQVuserKeyingMaterial"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence ASN1Sequence"/> with MQVuserKeyingMaterial inside it.
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static MQVuserKeyingMaterial getInstance(object obj)
		{
			if (obj is MQVuserKeyingMaterial)
			{
				return (MQVuserKeyingMaterial)obj;
			}
			else if (obj != null)
			{
				return new MQVuserKeyingMaterial(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual OriginatorPublicKey getEphemeralPublicKey()
		{
			return ephemeralPublicKey;
		}

		public virtual ASN1OctetString getAddedukm()
		{
			return addedukm;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();
			v.add(ephemeralPublicKey);

			if (addedukm != null)
			{
				v.add(new DERTaggedObject(true, 0, addedukm));
			}

			return new DERSequence(v);
		}
	}

}