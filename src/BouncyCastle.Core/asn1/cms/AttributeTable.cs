using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.cms
{


	/// <summary>
	/// This is helper tool to construct <seealso cref="Attributes"/> sets.
	/// </summary>
	public class AttributeTable
	{
		private Hashtable attributes = new Hashtable();

		public AttributeTable(Hashtable attrs)
		{
			attributes = copyTable(attrs);
		}

		public AttributeTable(ASN1EncodableVector v)
		{
			for (int i = 0; i != v.size(); i++)
			{
				Attribute a = Attribute.getInstance(v.get(i));

				addAttribute(a.getAttrType(), a);
			}
		}

		public AttributeTable(ASN1Set s)
		{
			for (int i = 0; i != s.size(); i++)
			{
				Attribute a = Attribute.getInstance(s.getObjectAt(i));

				addAttribute(a.getAttrType(), a);
			}
		}

		public AttributeTable(Attribute attr)
		{
			addAttribute(attr.getAttrType(), attr);
		}

		public AttributeTable(Attributes attrs) : this(ASN1Set.getInstance(attrs.toASN1Primitive()))
		{
		}

		private void addAttribute(ASN1ObjectIdentifier oid, Attribute a)
		{
			object value = attributes.get(oid);

			if (value == null)
			{
				attributes.put(oid, a);
			}
			else
			{
				Vector v;

				if (value is Attribute)
				{
					v = new Vector();

					v.addElement(value);
					v.addElement(a);
				}
				else
				{
					v = (Vector)value;

					v.addElement(a);
				}

				attributes.put(oid, v);
			}
		}

		/// <summary>
		/// Return the first attribute matching the OBJECT IDENTIFIER oid.
		/// </summary>
		/// <param name="oid"> type of attribute required. </param>
		/// <returns> first attribute found of type oid. </returns>
		public virtual Attribute get(ASN1ObjectIdentifier oid)
		{
			object value = attributes.get(oid);

			if (value is Vector)
			{
				return (Attribute)((Vector)value).elementAt(0);
			}

			return (Attribute)value;
		}

		/// <summary>
		/// Return all the attributes matching the OBJECT IDENTIFIER oid. The vector will be 
		/// empty if there are no attributes of the required type present.
		/// </summary>
		/// <param name="oid"> type of attribute required. </param>
		/// <returns> a vector of all the attributes found of type oid. </returns>
		public virtual ASN1EncodableVector getAll(ASN1ObjectIdentifier oid)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			object value = attributes.get(oid);

			if (value is Vector)
			{
				Enumeration e = ((Vector)value).elements();

				while (e.hasMoreElements())
				{
					v.add((Attribute)e.nextElement());
				}
			}
			else if (value != null)
			{
				v.add((Attribute)value);
			}

			return v;
		}

		public virtual int size()
		{
			int size = 0;

			for (Enumeration en = attributes.elements(); en.hasMoreElements();)
			{
				object o = en.nextElement();

				if (o is Vector)
				{
					size += ((Vector)o).size();
				}
				else
				{
					size++;
				}
			}

			return size;
		}

		public virtual Hashtable toHashtable()
		{
			return copyTable(attributes);
		}

		public virtual ASN1EncodableVector toASN1EncodableVector()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();
			Enumeration e = attributes.elements();

			while (e.hasMoreElements())
			{
				object value = e.nextElement();

				if (value is Vector)
				{
					Enumeration en = ((Vector)value).elements();

					while (en.hasMoreElements())
					{
						v.add(Attribute.getInstance(en.nextElement()));
					}
				}
				else
				{
					v.add(Attribute.getInstance(value));
				}
			}

			return v;
		}

		public virtual Attributes toASN1Structure()
		{
			return new Attributes(this.toASN1EncodableVector());
		}

		private Hashtable copyTable(Hashtable @in)
		{
			Hashtable @out = new Hashtable();
			Enumeration e = @in.keys();

			while (e.hasMoreElements())
			{
				object key = e.nextElement();

				@out.put(key, @in.get(key));
			}

			return @out;
		}

		/// <summary>
		/// Return a new table with the passed in attribute added.
		/// </summary>
		/// <param name="attrType"> the type of the attribute to add. </param>
		/// <param name="attrValue"> the value corresponding to the attribute (will be wrapped in a SET). </param>
		/// <returns> a new table with the extra attribute in it. </returns>
		public virtual AttributeTable add(ASN1ObjectIdentifier attrType, ASN1Encodable attrValue)
		{
			AttributeTable newTable = new AttributeTable(attributes);

			newTable.addAttribute(attrType, new Attribute(attrType, new DERSet(attrValue)));

			return newTable;
		}

		public virtual AttributeTable remove(ASN1ObjectIdentifier attrType)
		{
			AttributeTable newTable = new AttributeTable(attributes);

			newTable.attributes.remove(attrType);

			return newTable;
		}
	}

}