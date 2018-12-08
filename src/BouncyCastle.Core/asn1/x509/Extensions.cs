using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x509
{


	public class Extensions : ASN1Object
	{
		private Hashtable extensions = new Hashtable();
		private Vector ordering = new Vector();

		public static Extensions getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static Extensions getInstance(object obj)
		{
			if (obj is Extensions)
			{
				return (Extensions)obj;
			}
			else if (obj != null)
			{
				return new Extensions(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		/// <summary>
		/// Constructor from ASN1Sequence.
		/// <para>
		/// The extensions are a list of constructed sequences, either with (OID, OctetString) or (OID, Boolean, OctetString)
		/// </para>
		/// </summary>
		private Extensions(ASN1Sequence seq)
		{
			Enumeration e = seq.getObjects();

			while (e.hasMoreElements())
			{
				Extension ext = Extension.getInstance(e.nextElement());

				if (extensions.containsKey(ext.getExtnId()))
				{
					throw new IllegalArgumentException("repeated extension found: " + ext.getExtnId());
				}

				extensions.put(ext.getExtnId(), ext);
				ordering.addElement(ext.getExtnId());
			}
		}

		/// <summary>
		/// Base Constructor
		/// </summary>
		/// <param name="extension"> a single extension. </param>
		public Extensions(Extension extension)
		{
			this.ordering.addElement(extension.getExtnId());
			this.extensions.put(extension.getExtnId(), extension);
		}

		/// <summary>
		/// Base Constructor
		/// </summary>
		/// <param name="extensions"> an array of extensions. </param>
		public Extensions(Extension[] extensions)
		{
			for (int i = 0; i != extensions.Length; i++)
			{
				Extension ext = extensions[i];

				this.ordering.addElement(ext.getExtnId());
				this.extensions.put(ext.getExtnId(), ext);
			}
		}

		/// <summary>
		/// return an Enumeration of the extension field's object ids.
		/// </summary>
		public virtual Enumeration oids()
		{
			return ordering.elements();
		}

		/// <summary>
		/// return the extension represented by the object identifier
		/// passed in.
		/// </summary>
		/// <returns> the extension if it's present, null otherwise. </returns>
		public virtual Extension getExtension(ASN1ObjectIdentifier oid)
		{
			return (Extension)extensions.get(oid);
		}

		/// <summary>
		/// return the parsed value of the extension represented by the object identifier
		/// passed in.
		/// </summary>
		/// <returns> the parsed value of the extension if it's present, null otherwise. </returns>
		public virtual ASN1Encodable getExtensionParsedValue(ASN1ObjectIdentifier oid)
		{
			Extension ext = this.getExtension(oid);

			if (ext != null)
			{
				return ext.getParsedValue();
			}

			return null;
		}

		/// <summary>
		/// <pre>
		///     Extensions        ::=   SEQUENCE SIZE (1..MAX) OF Extension
		/// 
		///     Extension         ::=   SEQUENCE {
		///        extnId            EXTENSION.&amp;id ({ExtensionSet}),
		///        critical          BOOLEAN DEFAULT FALSE,
		///        extnValue         OCTET STRING }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector vec = new ASN1EncodableVector();
			Enumeration e = ordering.elements();

			while (e.hasMoreElements())
			{
				ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();
				Extension ext = (Extension)extensions.get(oid);

				vec.add(ext);
			}

			return new DERSequence(vec);
		}

		public virtual bool equivalent(Extensions other)
		{
			if (extensions.size() != other.extensions.size())
			{
				return false;
			}

			Enumeration e1 = extensions.keys();

			while (e1.hasMoreElements())
			{
				object key = e1.nextElement();

				if (!extensions.get(key).Equals(other.extensions.get(key)))
				{
					return false;
				}
			}

			return true;
		}

		public virtual ASN1ObjectIdentifier[] getExtensionOIDs()
		{
			return toOidArray(ordering);
		}

		public virtual ASN1ObjectIdentifier[] getNonCriticalExtensionOIDs()
		{
			return getExtensionOIDs(false);
		}

		public virtual ASN1ObjectIdentifier[] getCriticalExtensionOIDs()
		{
			return getExtensionOIDs(true);
		}

		private ASN1ObjectIdentifier[] getExtensionOIDs(bool isCritical)
		{
			Vector oidVec = new Vector();

			for (int i = 0; i != ordering.size(); i++)
			{
				object oid = ordering.elementAt(i);

				if (((Extension)extensions.get(oid)).isCritical() == isCritical)
				{
					oidVec.addElement(oid);
				}
			}

			return toOidArray(oidVec);
		}

		private ASN1ObjectIdentifier[] toOidArray(Vector oidVec)
		{
			ASN1ObjectIdentifier[] oids = new ASN1ObjectIdentifier[oidVec.size()];

			for (int i = 0; i != oids.Length; i++)
			{
				oids[i] = (ASN1ObjectIdentifier)oidVec.elementAt(i);
			}
			return oids;
		}
	}

}