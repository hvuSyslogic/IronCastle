using org.bouncycastle.asn1.cmp;
using org.bouncycastle.asn1.x509;

namespace org.bouncycastle.asn1.crmf
{
			
	/// <summary>
	/// Password-based MAC value for use with POPOSigningKeyInput.
	/// </summary>
	public class PKMACValue : ASN1Object
	{
		private AlgorithmIdentifier algId;
		private DERBitString value;

		private PKMACValue(ASN1Sequence seq)
		{
			algId = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
			value = DERBitString.getInstance(seq.getObjectAt(1));
		}

		public static PKMACValue getInstance(object o)
		{
			if (o is PKMACValue)
			{
				return (PKMACValue)o;
			}

			if (o != null)
			{
				return new PKMACValue(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public static PKMACValue getInstance(ASN1TaggedObject obj, bool isExplicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, isExplicit));
		}

		/// <summary>
		/// Creates a new PKMACValue. </summary>
		/// <param name="params"> parameters for password-based MAC </param>
		/// <param name="value"> MAC of the DER-encoded SubjectPublicKeyInfo </param>
		public PKMACValue(PBMParameter @params, DERBitString value) : this(new AlgorithmIdentifier(org.bouncycastle.asn1.cmp.CMPObjectIdentifiers_Fields.passwordBasedMac, @params), value)
		{
		}

		/// <summary>
		/// Creates a new PKMACValue. </summary>
		/// <param name="aid"> CMPObjectIdentifiers.passwordBasedMAC, with PBMParameter </param>
		/// <param name="value"> MAC of the DER-encoded SubjectPublicKeyInfo </param>
		public PKMACValue(AlgorithmIdentifier aid, DERBitString value)
		{
			this.algId = aid;
			this.value = value;
		}

		public virtual AlgorithmIdentifier getAlgId()
		{
			return algId;
		}

		public virtual DERBitString getValue()
		{
			return value;
		}

		/// <summary>
		/// <pre>
		/// PKMACValue ::= SEQUENCE {
		///      algId  AlgorithmIdentifier,
		///      -- algorithm value shall be PasswordBasedMac 1.2.840.113533.7.66.13
		///      -- parameter value is PBMParameter
		///      value  BIT STRING }
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(algId);
			v.add(value);

			return new DERSequence(v);
		}
	}

}