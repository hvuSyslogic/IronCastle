using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509
{

	/// <summary>
	/// Implementation of the RoleSyntax object as specified by the RFC3281.
	/// 
	/// <pre>
	/// RoleSyntax ::= SEQUENCE {
	///                 roleAuthority  [0] GeneralNames OPTIONAL,
	///                 roleName       [1] GeneralName
	///           } 
	/// </pre>
	/// </summary>
	public class RoleSyntax : ASN1Object
	{
		private GeneralNames roleAuthority;
		private GeneralName roleName;

		/// <summary>
		/// RoleSyntax factory method. </summary>
		/// <param name="obj"> the object used to construct an instance of <code>
		/// RoleSyntax</code>. It must be an instance of <code>RoleSyntax
		/// </code> or <code>ASN1Sequence</code>. </param>
		/// <returns> the instance of <code>RoleSyntax</code> built from the
		/// supplied object. </returns>
		/// <exception cref="IllegalArgumentException"> if the object passed
		/// to the factory is not an instance of <code>RoleSyntax</code> or
		/// <code>ASN1Sequence</code>. </exception>
		public static RoleSyntax getInstance(object obj)
		{

			if (obj is RoleSyntax)
			{
				return (RoleSyntax)obj;
			}
			else if (obj != null)
			{
				return new RoleSyntax(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		/// <summary>
		/// Constructor. </summary>
		/// <param name="roleAuthority"> the role authority of this RoleSyntax. </param>
		/// <param name="roleName">    the role name of this RoleSyntax. </param>
		public RoleSyntax(GeneralNames roleAuthority, GeneralName roleName)
		{
			if (roleName == null || roleName.getTagNo() != GeneralName.uniformResourceIdentifier || ((ASN1String)roleName.getName()).getString().Equals(""))
			{
				throw new IllegalArgumentException("the role name MUST be non empty and MUST " + "use the URI option of GeneralName");
			}
			this.roleAuthority = roleAuthority;
			this.roleName = roleName;
		}

		/// <summary>
		/// Constructor. Invoking this constructor is the same as invoking
		/// <code>new RoleSyntax(null, roleName)</code>. </summary>
		/// <param name="roleName">    the role name of this RoleSyntax. </param>
		public RoleSyntax(GeneralName roleName) : this(null, roleName)
		{
		}

		/// <summary>
		/// Utility constructor. Takes a <code>String</code> argument representing
		/// the role name, builds a <code>GeneralName</code> to hold the role name
		/// and calls the constructor that takes a <code>GeneralName</code>. </summary>
		/// <param name="roleName"> </param>
		public RoleSyntax(string roleName) : this(new GeneralName(GeneralName.uniformResourceIdentifier, (string.ReferenceEquals(roleName, null))? "": roleName))
		{
		}

		/// <summary>
		/// Constructor that builds an instance of <code>RoleSyntax</code> by
		/// extracting the encoded elements from the <code>ASN1Sequence</code>
		/// object supplied. </summary>
		/// <param name="seq">    an instance of <code>ASN1Sequence</code> that holds
		/// the encoded elements used to build this <code>RoleSyntax</code>. </param>
		private RoleSyntax(ASN1Sequence seq)
		{
			if (seq.size() < 1 || seq.size() > 2)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}

			for (int i = 0; i != seq.size(); i++)
			{
				ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(seq.getObjectAt(i));
				switch (taggedObject.getTagNo())
				{
				case 0:
					roleAuthority = GeneralNames.getInstance(taggedObject, false);
					break;
				case 1:
					roleName = GeneralName.getInstance(taggedObject, true);
					break;
				default:
					throw new IllegalArgumentException("Unknown tag in RoleSyntax");
				}
			}
		}

		/// <summary>
		/// Gets the role authority of this RoleSyntax. </summary>
		/// <returns>    an instance of <code>GeneralNames</code> holding the
		/// role authority of this RoleSyntax. </returns>
		public virtual GeneralNames getRoleAuthority()
		{
			return this.roleAuthority;
		}

		/// <summary>
		/// Gets the role name of this RoleSyntax. </summary>
		/// <returns>    an instance of <code>GeneralName</code> holding the
		/// role name of this RoleSyntax. </returns>
		public virtual GeneralName getRoleName()
		{
			return this.roleName;
		}

		/// <summary>
		/// Gets the role name as a <code>java.lang.String</code> object. </summary>
		/// <returns>    the role name of this RoleSyntax represented as a 
		/// <code>java.lang.String</code> object. </returns>
		public virtual string getRoleNameAsString()
		{
			ASN1String str = (ASN1String)this.roleName.getName();

			return str.getString();
		}

		/// <summary>
		/// Gets the role authority as a <code>String[]</code> object. </summary>
		/// <returns> the role authority of this RoleSyntax represented as a
		/// <code>String[]</code> array. </returns>
		public virtual string[] getRoleAuthorityAsString()
		{
			if (roleAuthority == null)
			{
				return new string[0];
			}

			GeneralName[] names = roleAuthority.getNames();
			string[] namesString = new string[names.Length];
			for (int i = 0; i < names.Length; i++)
			{
				ASN1Encodable value = names[i].getName();
				if (value is ASN1String)
				{
					namesString[i] = ((ASN1String)value).getString();
				}
				else
				{
					namesString[i] = value.ToString();
				}
			}
			return namesString;
		}

		/// <summary>
		/// Implementation of the method <code>toASN1Object</code> as
		/// required by the superclass <code>ASN1Encodable</code>.
		/// 
		/// <pre>
		/// RoleSyntax ::= SEQUENCE {
		///                 roleAuthority  [0] GeneralNames OPTIONAL,
		///                 roleName       [1] GeneralName
		///           } 
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();
			if (this.roleAuthority != null)
			{
				v.add(new DERTaggedObject(false, 0, roleAuthority));
			}
			v.add(new DERTaggedObject(true, 1, roleName));

			return new DERSequence(v);
		}

		public override string ToString()
		{
			StringBuffer buff = new StringBuffer("Name: " + this.getRoleNameAsString() + " - Auth: ");
			if (this.roleAuthority == null || roleAuthority.getNames().Length == 0)
			{
				buff.append("N/A");
			}
			else
			{
				string[] names = this.getRoleAuthorityAsString();
				buff.append('[').append(names[0]);
				for (int i = 1; i < names.Length; i++)
				{
						buff.append(", ").append(names[i]);
				}
				buff.append(']');
			}
			return buff.ToString();
		}
	}

}