using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.smime
{

			
	/// <summary>
	/// Handler class for dealing with S/MIME Capabilities
	/// </summary>
	public class SMIMECapabilities : ASN1Object
	{
		/// <summary>
		/// general preferences
		/// </summary>
		public static readonly ASN1ObjectIdentifier preferSignedData = PKCSObjectIdentifiers_Fields.preferSignedData;
		public static readonly ASN1ObjectIdentifier canNotDecryptAny = PKCSObjectIdentifiers_Fields.canNotDecryptAny;
		public static readonly ASN1ObjectIdentifier sMIMECapabilitesVersions = PKCSObjectIdentifiers_Fields.sMIMECapabilitiesVersions;

		/// <summary>
		/// encryption algorithms preferences
		/// </summary>
		public static readonly ASN1ObjectIdentifier aes256_CBC = NISTObjectIdentifiers_Fields.id_aes256_CBC;
		public static readonly ASN1ObjectIdentifier aes192_CBC = NISTObjectIdentifiers_Fields.id_aes192_CBC;
		public static readonly ASN1ObjectIdentifier aes128_CBC = NISTObjectIdentifiers_Fields.id_aes128_CBC;
		public static readonly ASN1ObjectIdentifier idea_CBC = new ASN1ObjectIdentifier("1.3.6.1.4.1.188.7.1.1.2");
		public static readonly ASN1ObjectIdentifier cast5_CBC = new ASN1ObjectIdentifier("1.2.840.113533.7.66.10");
		public static readonly ASN1ObjectIdentifier dES_CBC = new ASN1ObjectIdentifier("1.3.14.3.2.7");
		public static readonly ASN1ObjectIdentifier dES_EDE3_CBC = PKCSObjectIdentifiers_Fields.des_EDE3_CBC;
		public static readonly ASN1ObjectIdentifier rC2_CBC = PKCSObjectIdentifiers_Fields.RC2_CBC;

		private ASN1Sequence capabilities;

		/// <summary>
		/// return an Attribute object from the given object.
		/// </summary>
		/// <param name="o"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static SMIMECapabilities getInstance(object o)
		{
			if (o == null || o is SMIMECapabilities)
			{
				return (SMIMECapabilities)o;
			}

			if (o is ASN1Sequence)
			{
				return new SMIMECapabilities((ASN1Sequence)o);
			}

			if (o is Attribute)
			{
				return new SMIMECapabilities((ASN1Sequence)(((Attribute)o).getAttrValues().getObjectAt(0)));
			}

			throw new IllegalArgumentException("unknown object in factory: " + o.GetType().getName());
		}

		public SMIMECapabilities(ASN1Sequence seq)
		{
			capabilities = seq;
		}

		/// <summary>
		/// returns a vector with 0 or more objects of all the capabilities
		/// matching the passed in capability OID. If the OID passed is null the
		/// entire set is returned.
		/// </summary>
		public virtual Vector getCapabilities(ASN1ObjectIdentifier capability)
		{
			Enumeration e = capabilities.getObjects();
			Vector list = new Vector();

			if (capability == null)
			{
				while (e.hasMoreElements())
				{
					SMIMECapability cap = SMIMECapability.getInstance(e.nextElement());

					list.addElement(cap);
				}
			}
			else
			{
				while (e.hasMoreElements())
				{
					SMIMECapability cap = SMIMECapability.getInstance(e.nextElement());

					if (capability.Equals(cap.getCapabilityID()))
					{
						list.addElement(cap);
					}
				}
			}

			return list;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		/// SMIMECapabilities ::= SEQUENCE OF SMIMECapability
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			return capabilities;
		}
	}

}