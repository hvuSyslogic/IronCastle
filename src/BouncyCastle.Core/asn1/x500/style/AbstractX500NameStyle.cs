using System.IO;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x500.style
{


	/// <summary>
	/// This class provides some default behavior and common implementation for a
	/// X500NameStyle. It should be easily extendable to support implementing the
	/// desired X500NameStyle.
	/// </summary>
	public abstract class AbstractX500NameStyle : X500NameStyle
	{
		public abstract string[] oidToAttrNames(ASN1ObjectIdentifier oid);
		public abstract string oidToDisplayName(ASN1ObjectIdentifier oid);
		public abstract string ToString(X500Name name);
		public abstract RDN[] fromString(string dirName);
		public abstract ASN1ObjectIdentifier attrNameToOID(string attrName);

		/// <summary>
		/// Tool function to shallow copy a Hashtable.
		/// </summary>
		/// <param name="paramsMap"> table to copy </param>
		/// <returns> the copy of the table </returns>
		public static Hashtable copyHashTable(Hashtable paramsMap)
		{
			Hashtable newTable = new Hashtable();

			Enumeration keys = paramsMap.keys();
			while (keys.hasMoreElements())
			{
				object key = keys.nextElement();
				newTable.put(key, paramsMap.get(key));
			}

			return newTable;
		}

		private int calcHashCode(ASN1Encodable enc)
		{
			string value = IETFUtils.valueToString(enc);
			value = IETFUtils.canonicalize(value);
			return value.GetHashCode();
		}

		public virtual int calculateHashCode(X500Name name)
		{
			int hashCodeValue = 0;
			RDN[] rdns = name.getRDNs();

			// this needs to be order independent, like equals
			for (int i = 0; i != rdns.Length; i++)
			{
				if (rdns[i].isMultiValued())
				{
					AttributeTypeAndValue[] atv = rdns[i].getTypesAndValues();

					for (int j = 0; j != atv.Length; j++)
					{
						hashCodeValue ^= atv[j].getType().GetHashCode();
						hashCodeValue ^= calcHashCode(atv[j].getValue());
					}
				}
				else
				{
					hashCodeValue ^= rdns[i].getFirst().getType().GetHashCode();
					hashCodeValue ^= calcHashCode(rdns[i].getFirst().getValue());
				}
			}

			return hashCodeValue;
		}


		/// <summary>
		/// For all string values starting with '#' is assumed, that these are
		/// already valid ASN.1 objects encoded in hex.
		/// <para>
		/// All other string values are send to
		/// <seealso cref="AbstractX500NameStyle#encodeStringValue(ASN1ObjectIdentifier, String)"/>.
		/// </para>
		/// Subclasses should overwrite
		/// <seealso cref="AbstractX500NameStyle#encodeStringValue(ASN1ObjectIdentifier, String)"/>
		/// to change the encoding of specific types.
		/// </summary>
		/// <param name="oid"> the DN name of the value. </param>
		/// <param name="value"> the String representation of the value. </param>
		public virtual ASN1Encodable stringToValue(ASN1ObjectIdentifier oid, string value)
		{
			if (value.Length != 0 && value[0] == '#')
			{
				try
				{
					return IETFUtils.valueFromHexString(value, 1);
				}
				catch (IOException)
				{
					throw new ASN1ParsingException("can't recode value for oid " + oid.getId());
				}
			}

			if (value.Length != 0 && value[0] == '\\')
			{
				value = value.Substring(1);
			}

			return encodeStringValue(oid, value);
		}

		/// <summary>
		/// Encoded every value into a UTF8String.
		/// <para>
		/// Subclasses should overwrite
		/// this method to change the encoding of specific types.
		/// </para>
		/// </summary>
		/// <param name="oid"> the DN oid of the value </param>
		/// <param name="value"> the String representation of the value </param>
		/// <returns> a the value encoded into a ASN.1 object. Never returns <code>null</code>. </returns>
		public virtual ASN1Encodable encodeStringValue(ASN1ObjectIdentifier oid, string value)
		{
			return new DERUTF8String(value);
		}

		public virtual bool areEqual(X500Name name1, X500Name name2)
		{
			RDN[] rdns1 = name1.getRDNs();
			RDN[] rdns2 = name2.getRDNs();

			if (rdns1.Length != rdns2.Length)
			{
				return false;
			}

			bool reverse = false;

			if (rdns1[0].getFirst() != null && rdns2[0].getFirst() != null)
			{
				reverse = !rdns1[0].getFirst().getType().Equals(rdns2[0].getFirst().getType()); // guess forward
			}

			for (int i = 0; i != rdns1.Length; i++)
			{
				if (!foundMatch(reverse, rdns1[i], rdns2))
				{
					return false;
				}
			}

			return true;
		}

		private bool foundMatch(bool reverse, RDN rdn, RDN[] possRDNs)
		{
			if (reverse)
			{
				for (int i = possRDNs.Length - 1; i >= 0; i--)
				{
					if (possRDNs[i] != null && rdnAreEqual(rdn, possRDNs[i]))
					{
						possRDNs[i] = null;
						return true;
					}
				}
			}
			else
			{
				for (int i = 0; i != possRDNs.Length; i++)
				{
					if (possRDNs[i] != null && rdnAreEqual(rdn, possRDNs[i]))
					{
						possRDNs[i] = null;
						return true;
					}
				}
			}

			return false;
		}

		public virtual bool rdnAreEqual(RDN rdn1, RDN rdn2)
		{
			return IETFUtils.rDNAreEqual(rdn1, rdn2);
		}
	}

}