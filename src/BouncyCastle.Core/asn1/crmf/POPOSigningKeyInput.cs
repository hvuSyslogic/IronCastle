using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.crmf
{
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

	public class POPOSigningKeyInput : ASN1Object
	{
		private GeneralName sender;
		private PKMACValue publicKeyMAC;
		private SubjectPublicKeyInfo publicKey;

		private POPOSigningKeyInput(ASN1Sequence seq)
		{
			ASN1Encodable authInfo = seq.getObjectAt(0);

			if (authInfo is ASN1TaggedObject)
			{
				ASN1TaggedObject tagObj = (ASN1TaggedObject)authInfo;
				if (tagObj.getTagNo() != 0)
				{
					throw new IllegalArgumentException("Unknown authInfo tag: " + tagObj.getTagNo());
				}
				sender = GeneralName.getInstance(tagObj.getObject());
			}
			else
			{
				publicKeyMAC = PKMACValue.getInstance(authInfo);
			}

			publicKey = SubjectPublicKeyInfo.getInstance(seq.getObjectAt(1));
		}

		public static POPOSigningKeyInput getInstance(object o)
		{
			if (o is POPOSigningKeyInput)
			{
				return (POPOSigningKeyInput)o;
			}

			if (o != null)
			{
				return new POPOSigningKeyInput(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		/// <summary>
		///  Creates a new POPOSigningKeyInput with sender name as authInfo.
		/// </summary>
		public POPOSigningKeyInput(GeneralName sender, SubjectPublicKeyInfo spki)
		{
			this.sender = sender;
			this.publicKey = spki;
		}

		/// <summary>
		/// Creates a new POPOSigningKeyInput using password-based MAC.
		/// </summary>
		public POPOSigningKeyInput(PKMACValue pkmac, SubjectPublicKeyInfo spki)
		{
			this.publicKeyMAC = pkmac;
			this.publicKey = spki;
		}

		/// <summary>
		/// Returns the sender field, or null if authInfo is publicKeyMAC
		/// </summary>
		public virtual GeneralName getSender()
		{
			return sender;
		}

		/// <summary>
		/// Returns the publicKeyMAC field, or null if authInfo is sender
		/// </summary>
		public virtual PKMACValue getPublicKeyMAC()
		{
			return publicKeyMAC;
		}

		public virtual SubjectPublicKeyInfo getPublicKey()
		{
			return publicKey;
		}

		/// <summary>
		/// <pre>
		/// POPOSigningKeyInput ::= SEQUENCE {
		///        authInfo             CHOICE {
		///                                 sender              [0] GeneralName,
		///                                 -- used only if an authenticated identity has been
		///                                 -- established for the sender (e.g., a DN from a
		///                                 -- previously-issued and currently-valid certificate
		///                                 publicKeyMAC        PKMACValue },
		///                                 -- used if no authenticated GeneralName currently exists for
		///                                 -- the sender; publicKeyMAC contains a password-based MAC
		///                                 -- on the DER-encoded value of publicKey
		///        publicKey           SubjectPublicKeyInfo }  -- from CertTemplate
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			if (sender != null)
			{
				v.add(new DERTaggedObject(false, 0, sender));
			}
			else
			{
				v.add(publicKeyMAC);
			}

			v.add(publicKey);

			return new DERSequence(v);
		}
	}

}