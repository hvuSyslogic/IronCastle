using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.smime
{
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

	public class SMIMECapability : ASN1Object
	{
		/// <summary>
		/// general preferences
		/// </summary>
		public static readonly ASN1ObjectIdentifier preferSignedData = PKCSObjectIdentifiers_Fields.preferSignedData;
		public static readonly ASN1ObjectIdentifier canNotDecryptAny = PKCSObjectIdentifiers_Fields.canNotDecryptAny;
		public static readonly ASN1ObjectIdentifier sMIMECapabilitiesVersions = PKCSObjectIdentifiers_Fields.sMIMECapabilitiesVersions;

		/// <summary>
		/// encryption algorithms preferences
		/// </summary>
		public static readonly ASN1ObjectIdentifier dES_CBC = new ASN1ObjectIdentifier("1.3.14.3.2.7");
		public static readonly ASN1ObjectIdentifier dES_EDE3_CBC = PKCSObjectIdentifiers_Fields.des_EDE3_CBC;
		public static readonly ASN1ObjectIdentifier rC2_CBC = PKCSObjectIdentifiers_Fields.RC2_CBC;
		public static readonly ASN1ObjectIdentifier aES128_CBC = NISTObjectIdentifiers_Fields.id_aes128_CBC;
		public static readonly ASN1ObjectIdentifier aES192_CBC = NISTObjectIdentifiers_Fields.id_aes192_CBC;
		public static readonly ASN1ObjectIdentifier aES256_CBC = NISTObjectIdentifiers_Fields.id_aes256_CBC;

		private ASN1ObjectIdentifier capabilityID;
		private ASN1Encodable parameters;

		public SMIMECapability(ASN1Sequence seq)
		{
			capabilityID = (ASN1ObjectIdentifier)seq.getObjectAt(0);

			if (seq.size() > 1)
			{
				parameters = (ASN1Primitive)seq.getObjectAt(1);
			}
		}

		public SMIMECapability(ASN1ObjectIdentifier capabilityID, ASN1Encodable parameters)
		{
			this.capabilityID = capabilityID;
			this.parameters = parameters;
		}

		public static SMIMECapability getInstance(object obj)
		{
			if (obj == null || obj is SMIMECapability)
			{
				return (SMIMECapability)obj;
			}

			if (obj is ASN1Sequence)
			{
				return new SMIMECapability((ASN1Sequence)obj);
			}

			throw new IllegalArgumentException("Invalid SMIMECapability");
		}

		public virtual ASN1ObjectIdentifier getCapabilityID()
		{
			return capabilityID;
		}

		public virtual ASN1Encodable getParameters()
		{
			return parameters;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre> 
		/// SMIMECapability ::= SEQUENCE {
		///     capabilityID OBJECT IDENTIFIER,
		///     parameters ANY DEFINED BY capabilityID OPTIONAL 
		/// }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(capabilityID);

			if (parameters != null)
			{
				v.add(parameters);
			}

			return new DERSequence(v);
		}
	}

}