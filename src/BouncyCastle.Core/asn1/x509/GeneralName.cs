using System;
using System.IO;
using BouncyCastle.Core.Port.java.util;
using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509
{

	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using IPAddress = org.bouncycastle.util.IPAddress;

	/// <summary>
	/// The GeneralName object.
	/// <pre>
	/// GeneralName ::= CHOICE {
	///      otherName                       [0]     OtherName,
	///      rfc822Name                      [1]     IA5String,
	///      dNSName                         [2]     IA5String,
	///      x400Address                     [3]     ORAddress,
	///      directoryName                   [4]     Name,
	///      ediPartyName                    [5]     EDIPartyName,
	///      uniformResourceIdentifier       [6]     IA5String,
	///      iPAddress                       [7]     OCTET STRING,
	///      registeredID                    [8]     OBJECT IDENTIFIER}
	/// 
	/// OtherName ::= SEQUENCE {
	///      type-id    OBJECT IDENTIFIER,
	///      value      [0] EXPLICIT ANY DEFINED BY type-id }
	/// 
	/// EDIPartyName ::= SEQUENCE {
	///      nameAssigner            [0]     DirectoryString OPTIONAL,
	///      partyName               [1]     DirectoryString }
	/// 
	/// Name ::= CHOICE { RDNSequence }
	/// </pre>
	/// </summary>
	public class GeneralName : ASN1Object, ASN1Choice
	{
		public const int otherName = 0;
		public const int rfc822Name = 1;
		public const int dNSName = 2;
		public const int x400Address = 3;
		public const int directoryName = 4;
		public const int ediPartyName = 5;
		public const int uniformResourceIdentifier = 6;
		public const int iPAddress = 7;
		public const int registeredID = 8;

		private ASN1Encodable obj;
		private int tag;

		/// @deprecated use X500Name constructor. 
		/// <param name="dirName"> </param>
			public GeneralName(X509Name dirName)
			{
			this.obj = X500Name.getInstance(dirName);
			this.tag = 4;
			}

		public GeneralName(X500Name dirName)
		{
			this.obj = dirName;
			this.tag = 4;
		}

		/// <summary>
		/// When the subjectAltName extension contains an Internet mail address,
		/// the address MUST be included as an rfc822Name. The format of an
		/// rfc822Name is an "addr-spec" as defined in RFC 822 [RFC 822].
		/// 
		/// When the subjectAltName extension contains a domain name service
		/// label, the domain name MUST be stored in the dNSName (an IA5String).
		/// The name MUST be in the "preferred name syntax," as specified by RFC
		/// 1034 [RFC 1034].
		/// 
		/// When the subjectAltName extension contains a URI, the name MUST be
		/// stored in the uniformResourceIdentifier (an IA5String). The name MUST
		/// be a non-relative URL, and MUST follow the URL syntax and encoding
		/// rules specified in [RFC 1738].  The name must include both a scheme
		/// (e.g., "http" or "ftp") and a scheme-specific-part.  The scheme-
		/// specific-part must include a fully qualified domain name or IP
		/// address as the host.
		/// 
		/// When the subjectAltName extension contains a iPAddress, the address
		/// MUST be stored in the octet string in "network byte order," as
		/// specified in RFC 791 [RFC 791]. The least significant bit (LSB) of
		/// each octet is the LSB of the corresponding byte in the network
		/// address. For IP Version 4, as specified in RFC 791, the octet string
		/// MUST contain exactly four octets.  For IP Version 6, as specified in
		/// RFC 1883, the octet string MUST contain exactly sixteen octets [RFC
		/// 1883].
		/// </summary>
		public GeneralName(int tag, ASN1Encodable name)
		{
			this.obj = name;
			this.tag = tag;
		}

		/// <summary>
		/// Create a GeneralName for the given tag from the passed in String.
		/// <para>
		/// This constructor can handle:
		/// <ul>
		/// <li>rfc822Name
		/// <li>iPAddress
		/// <li>directoryName
		/// <li>dNSName
		/// <li>uniformResourceIdentifier
		/// <li>registeredID
		/// </ul>
		/// For x400Address, otherName and ediPartyName there is no common string
		/// format defined.
		/// </para>
		/// <para>
		/// Note: A directory name can be encoded in different ways into a byte
		/// representation. Be aware of this if the byte representation is used for
		/// comparing results.
		/// 
		/// </para>
		/// </summary>
		/// <param name="tag"> tag number </param>
		/// <param name="name"> string representation of name </param>
		/// <exception cref="IllegalArgumentException"> if the string encoding is not correct or     *             not supported. </exception>
		public GeneralName(int tag, string name)
		{
			this.tag = tag;

			if (tag == rfc822Name || tag == dNSName || tag == uniformResourceIdentifier)
			{
				this.obj = new DERIA5String(name);
			}
			else if (tag == registeredID)
			{
				this.obj = new ASN1ObjectIdentifier(name);
			}
			else if (tag == directoryName)
			{
				this.obj = new X500Name(name);
			}
			else if (tag == iPAddress)
			{
				byte[] enc = toGeneralNameEncoding(name);
				if (enc != null)
				{
					this.obj = new DEROctetString(enc);
				}
				else
				{
					throw new IllegalArgumentException("IP Address is invalid");
				}
			}
			else
			{
				throw new IllegalArgumentException("can't process String for tag: " + tag);
			}
		}

		public static GeneralName getInstance(object obj)
		{
			if (obj == null || obj is GeneralName)
			{
				return (GeneralName)obj;
			}

			if (obj is ASN1TaggedObject)
			{
				ASN1TaggedObject tagObj = (ASN1TaggedObject)obj;
				int tag = tagObj.getTagNo();

				switch (tag)
				{
				case otherName:
					return new GeneralName(tag, ASN1Sequence.getInstance(tagObj, false));
				case rfc822Name:
					return new GeneralName(tag, DERIA5String.getInstance(tagObj, false));
				case dNSName:
					return new GeneralName(tag, DERIA5String.getInstance(tagObj, false));
				case x400Address:
					throw new IllegalArgumentException("unknown tag: " + tag);
				case directoryName:
					return new GeneralName(tag, X500Name.getInstance(tagObj, true));
				case ediPartyName:
					return new GeneralName(tag, ASN1Sequence.getInstance(tagObj, false));
				case uniformResourceIdentifier:
					return new GeneralName(tag, DERIA5String.getInstance(tagObj, false));
				case iPAddress:
					return new GeneralName(tag, ASN1OctetString.getInstance(tagObj, false));
				case registeredID:
					return new GeneralName(tag, ASN1ObjectIdentifier.getInstance(tagObj, false));
				}
			}

			if (obj is byte[])
			{
				try
				{
					return getInstance(ASN1Primitive.fromByteArray((byte[])obj));
				}
				catch (IOException)
				{
					throw new IllegalArgumentException("unable to parse encoded general name");
				}
			}

			throw new IllegalArgumentException("unknown object in getInstance: " + obj.GetType().getName());
		}

		public static GeneralName getInstance(ASN1TaggedObject tagObj, bool @explicit)
		{
			return GeneralName.getInstance(ASN1TaggedObject.getInstance(tagObj, true));
		}

		public virtual int getTagNo()
		{
			return tag;
		}

		public virtual ASN1Encodable getName()
		{
			return obj;
		}

		public override string ToString()
		{
			StringBuffer buf = new StringBuffer();

			buf.append(tag);
			buf.append(": ");
			switch (tag)
			{
			case rfc822Name:
			case dNSName:
			case uniformResourceIdentifier:
				buf.append(DERIA5String.getInstance(obj).getString());
				break;
			case directoryName:
				buf.append(X500Name.getInstance(obj).ToString());
				break;
			default:
				buf.append(obj.ToString());
			break;
			}
			return buf.ToString();
		}

		private byte[] toGeneralNameEncoding(string ip)
		{
			if (IPAddress.isValidIPv6WithNetmask(ip) || IPAddress.isValidIPv6(ip))
			{
				int slashIndex = ip.IndexOf('/');

				if (slashIndex < 0)
				{
					byte[] addr = new byte[16];
					int[] parsedIp = parseIPv6(ip);
					copyInts(parsedIp, addr, 0);

					return addr;
				}
				else
				{
					byte[] addr = new byte[32];
					int[] parsedIp = parseIPv6(ip.Substring(0, slashIndex));
					copyInts(parsedIp, addr, 0);
					string mask = ip.Substring(slashIndex + 1);
					if (mask.IndexOf(':') > 0)
					{
						parsedIp = parseIPv6(mask);
					}
					else
					{
						parsedIp = parseMask(mask);
					}
					copyInts(parsedIp, addr, 16);

					return addr;
				}
			}
			else if (IPAddress.isValidIPv4WithNetmask(ip) || IPAddress.isValidIPv4(ip))
			{
				int slashIndex = ip.IndexOf('/');

				if (slashIndex < 0)
				{
					byte[] addr = new byte[4];

					parseIPv4(ip, addr, 0);

					return addr;
				}
				else
				{
					byte[] addr = new byte[8];

					parseIPv4(ip.Substring(0, slashIndex), addr, 0);

					string mask = ip.Substring(slashIndex + 1);
					if (mask.IndexOf('.') > 0)
					{
						parseIPv4(mask, addr, 4);
					}
					else
					{
						parseIPv4Mask(mask, addr, 4);
					}

					return addr;
				}
			}

			return null;
		}

		private void parseIPv4Mask(string mask, byte[] addr, int offset)
		{
			int maskVal = int.Parse(mask);

			for (int i = 0; i != maskVal; i++)
			{
				addr[(i / 8) + offset] |= (byte)(1 << (7 - (i % 8)));
			}
		}

		private void parseIPv4(string ip, byte[] addr, int offset)
		{
			StringTokenizer sTok = new StringTokenizer(ip, "./");
			int index = 0;

			while (sTok.hasMoreTokens())
			{
				addr[offset + index++] = (byte)int.Parse(sTok.nextToken());
			}
		}

		private int[] parseMask(string mask)
		{
			int[] res = new int[8];
			int maskVal = int.Parse(mask);

			for (int i = 0; i != maskVal; i++)
			{
				res[i / 16] |= 1 << (15 - (i % 16));
			}
			return res;
		}

		private void copyInts(int[] parsedIp, byte[] addr, int offSet)
		{
			for (int i = 0; i != parsedIp.Length; i++)
			{
				addr[(i * 2) + offSet] = (byte)(parsedIp[i] >> 8);
				addr[(i * 2 + 1) + offSet] = (byte)parsedIp[i];
			}
		}

		private int[] parseIPv6(string ip)
		{
			StringTokenizer sTok = new StringTokenizer(ip, ":", true);
			int index = 0;
			int[] val = new int[8];

			if (ip[0] == ':' && ip[1] == ':')
			{
			   sTok.nextToken(); // skip the first one
			}

			int doubleColon = -1;

			while (sTok.hasMoreTokens())
			{
				string e = sTok.nextToken();

				if (e.Equals(":"))
				{
					doubleColon = index;
					val[index++] = 0;
				}
				else
				{
					if (e.IndexOf('.') < 0)
					{
						val[index++] = Convert.ToInt32(e, 16);
						if (sTok.hasMoreTokens())
						{
							sTok.nextToken();
						}
					}
					else
					{
						StringTokenizer eTok = new StringTokenizer(e, ".");

						val[index++] = (int.Parse(eTok.nextToken()) << 8) | int.Parse(eTok.nextToken());
						val[index++] = (int.Parse(eTok.nextToken()) << 8) | int.Parse(eTok.nextToken());
					}
				}
			}

			if (index != val.Length)
			{
				JavaSystem.arraycopy(val, doubleColon, val, val.Length - (index - doubleColon), index - doubleColon);
				for (int i = doubleColon; i != val.Length - (index - doubleColon); i++)
				{
					val[i] = 0;
				}
			}

			return val;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			if (tag == directoryName) // directoryName is explicitly tagged as it is a CHOICE
			{
				return new DERTaggedObject(true, tag, obj);
			}
			else
			{
				return new DERTaggedObject(false, tag, obj);
			}
		}
	}

}