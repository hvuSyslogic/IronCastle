using org.bouncycastle.asn1.x509;

namespace org.bouncycastle.asn1.cmp
{
	
	public class Challenge : ASN1Object
	{
		private AlgorithmIdentifier owf;
		private ASN1OctetString witness;
		private ASN1OctetString challenge;

		private Challenge(ASN1Sequence seq)
		{
			int index = 0;

			if (seq.size() == 3)
			{
				owf = AlgorithmIdentifier.getInstance(seq.getObjectAt(index++));
			}

			witness = ASN1OctetString.getInstance(seq.getObjectAt(index++));
			challenge = ASN1OctetString.getInstance(seq.getObjectAt(index));
		}

		public static Challenge getInstance(object o)
		{
			if (o is Challenge)
			{
				return (Challenge)o;
			}

			if (o != null)
			{
				return new Challenge(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public Challenge(byte[] witness, byte[] challenge) : this(null, witness, challenge)
		{
		}

		public Challenge(AlgorithmIdentifier owf, byte[] witness, byte[] challenge)
		{
			this.owf = owf;
			this.witness = new DEROctetString(witness);
			this.challenge = new DEROctetString(challenge);
		}

		public virtual AlgorithmIdentifier getOwf()
		{
			return owf;
		}

		public virtual byte[] getWitness()
		{
			return witness.getOctets();
		}

		public virtual byte[] getChallenge()
		{
			return challenge.getOctets();
		}

		/// <summary>
		/// <pre>
		/// Challenge ::= SEQUENCE {
		///                 owf                 AlgorithmIdentifier  OPTIONAL,
		/// 
		///                 -- MUST be present in the first Challenge; MAY be omitted in
		///                 -- any subsequent Challenge in POPODecKeyChallContent (if
		///                 -- omitted, then the owf used in the immediately preceding
		///                 -- Challenge is to be used).
		/// 
		///                 witness             OCTET STRING,
		///                 -- the result of applying the one-way function (owf) to a
		///                 -- randomly-generated INTEGER, A.  [Note that a different
		///                 -- INTEGER MUST be used for each Challenge.]
		///                 challenge           OCTET STRING
		///                 -- the encryption (under the public key for which the cert.
		///                 -- request is being made) of Rand, where Rand is specified as
		///                 --   Rand ::= SEQUENCE {
		///                 --      int      INTEGER,
		///                 --       - the randomly-generated INTEGER A (above)
		///                 --      sender   GeneralName
		///                 --       - the sender's name (as included in PKIHeader)
		///                 --   }
		///      }
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			addOptional(v, owf);
			v.add(witness);
			v.add(challenge);

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