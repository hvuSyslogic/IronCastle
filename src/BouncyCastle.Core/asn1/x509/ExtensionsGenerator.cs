using org.bouncycastle.asn1;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x509
{


	/// <summary>
	/// Generator for X.509 extensions
	/// </summary>
	public class ExtensionsGenerator
	{
		private Hashtable extensions = new Hashtable();
		private Vector extOrdering = new Vector();

		/// <summary>
		/// Reset the generator
		/// </summary>
		public virtual void reset()
		{
			extensions = new Hashtable();
			extOrdering = new Vector();
		}

		/// <summary>
		/// Add an extension with the given oid and the passed in value to be included
		/// in the OCTET STRING associated with the extension.
		/// </summary>
		/// <param name="oid">  OID for the extension. </param>
		/// <param name="critical">  true if critical, false otherwise. </param>
		/// <param name="value"> the ASN.1 object to be included in the extension. </param>
		public virtual void addExtension(ASN1ObjectIdentifier oid, bool critical, ASN1Encodable value)
		{
			this.addExtension(oid, critical, value.toASN1Primitive().getEncoded(ASN1Encoding_Fields.DER));
		}

		/// <summary>
		/// Add an extension with the given oid and the passed in byte array to be wrapped in the
		/// OCTET STRING associated with the extension.
		/// </summary>
		/// <param name="oid"> OID for the extension. </param>
		/// <param name="critical"> true if critical, false otherwise. </param>
		/// <param name="value"> the byte array to be wrapped. </param>
		public virtual void addExtension(ASN1ObjectIdentifier oid, bool critical, byte[] value)
		{
			if (extensions.containsKey(oid))
			{
				throw new IllegalArgumentException("extension " + oid + " already added");
			}

			extOrdering.addElement(oid);
			extensions.put(oid, new Extension(oid, critical, new DEROctetString(value)));
		}

		/// <summary>
		/// Add a given extension.
		/// </summary>
		/// <param name="extension"> the full extension value. </param>
		public virtual void addExtension(Extension extension)
		{
			if (extensions.containsKey(extension.getExtnId()))
			{
				throw new IllegalArgumentException("extension " + extension.getExtnId() + " already added");
			}

			extOrdering.addElement(extension.getExtnId());
			extensions.put(extension.getExtnId(), extension);
		}

		/// <summary>
		/// Return true if there are no extension present in this generator.
		/// </summary>
		/// <returns> true if empty, false otherwise </returns>
		public virtual bool isEmpty()
		{
			return extOrdering.isEmpty();
		}

		/// <summary>
		/// Generate an Extensions object based on the current state of the generator.
		/// </summary>
		/// <returns>  an X09Extensions object. </returns>
		public virtual Extensions generate()
		{
			Extension[] exts = new Extension[extOrdering.size()];

			for (int i = 0; i != extOrdering.size(); i++)
			{
				exts[i] = (Extension)extensions.get(extOrdering.elementAt(i));
			}

			return new Extensions(exts);
		}
	}

}