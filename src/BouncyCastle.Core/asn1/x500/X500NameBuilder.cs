using org.bouncycastle.asn1.x500.style;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x500
{

	
	/// <summary>
	/// A builder class for making X.500 Name objects.
	/// </summary>
	public class X500NameBuilder
	{
		private X500NameStyle template;
		private Vector rdns = new Vector();

		/// <summary>
		/// Constructor using the default style (BCStyle).
		/// </summary>
		public X500NameBuilder() : this(BCStyle.INSTANCE)
		{
		}

		/// <summary>
		/// Constructor using a specified style.
		/// </summary>
		/// <param name="template"> the style template for string to DN conversion. </param>
		public X500NameBuilder(X500NameStyle template)
		{
			this.template = template;
		}

		/// <summary>
		/// Add an RDN based on a single OID and a string representation of its value.
		/// </summary>
		/// <param name="oid"> the OID for this RDN. </param>
		/// <param name="value"> the string representation of the value the OID refers to. </param>
		/// <returns> the current builder instance. </returns>
		public virtual X500NameBuilder addRDN(ASN1ObjectIdentifier oid, string value)
		{
			this.addRDN(oid, template.stringToValue(oid, value));

			return this;
		}

		/// <summary>
		/// Add an RDN based on a single OID and an ASN.1 value.
		/// </summary>
		/// <param name="oid"> the OID for this RDN. </param>
		/// <param name="value"> the ASN.1 value the OID refers to. </param>
		/// <returns> the current builder instance. </returns>
		public virtual X500NameBuilder addRDN(ASN1ObjectIdentifier oid, ASN1Encodable value)
		{
			rdns.addElement(new RDN(oid, value));

			return this;
		}

		/// <summary>
		/// Add an RDN based on the passed in AttributeTypeAndValue.
		/// </summary>
		/// <param name="attrTAndV"> the AttributeTypeAndValue to build the RDN from. </param>
		/// <returns> the current builder instance. </returns>
		public virtual X500NameBuilder addRDN(AttributeTypeAndValue attrTAndV)
		{
			rdns.addElement(new RDN(attrTAndV));

			return this;
		}

		/// <summary>
		/// Add a multi-valued RDN made up of the passed in OIDs and associated string values.
		/// </summary>
		/// <param name="oids"> the OIDs making up the RDN. </param>
		/// <param name="values"> the string representation of the values the OIDs refer to. </param>
		/// <returns> the current builder instance. </returns>
		public virtual X500NameBuilder addMultiValuedRDN(ASN1ObjectIdentifier[] oids, string[] values)
		{
			ASN1Encodable[] vals = new ASN1Encodable[values.Length];

			for (int i = 0; i != vals.Length; i++)
			{
				vals[i] = template.stringToValue(oids[i], values[i]);
			}

			return addMultiValuedRDN(oids, vals);
		}

		/// <summary>
		/// Add a multi-valued RDN made up of the passed in OIDs and associated ASN.1 values.
		/// </summary>
		/// <param name="oids"> the OIDs making up the RDN. </param>
		/// <param name="values"> the ASN.1 values the OIDs refer to. </param>
		/// <returns> the current builder instance. </returns>
		public virtual X500NameBuilder addMultiValuedRDN(ASN1ObjectIdentifier[] oids, ASN1Encodable[] values)
		{
			AttributeTypeAndValue[] avs = new AttributeTypeAndValue[oids.Length];

			for (int i = 0; i != oids.Length; i++)
			{
				avs[i] = new AttributeTypeAndValue(oids[i], values[i]);
			}

			return addMultiValuedRDN(avs);
		}

		/// <summary>
		/// Add an RDN based on the passed in AttributeTypeAndValues.
		/// </summary>
		/// <param name="attrTAndVs"> the AttributeTypeAndValues to build the RDN from. </param>
		/// <returns> the current builder instance. </returns>
		public virtual X500NameBuilder addMultiValuedRDN(AttributeTypeAndValue[] attrTAndVs)
		{
			rdns.addElement(new RDN(attrTAndVs));

			return this;
		}

		/// <summary>
		/// Build an X.500 name for the current builder state.
		/// </summary>
		/// <returns> a new X.500 name. </returns>
		public virtual X500Name build()
		{
			RDN[] vals = new RDN[rdns.size()];

			for (int i = 0; i != vals.Length; i++)
			{
				vals[i] = (RDN)rdns.elementAt(i);
			}

			return new X500Name(template, vals);
		}
	}
}