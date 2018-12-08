namespace org.bouncycastle.jce.provider
{

	public class PKIXPolicyNode : PolicyNode
	{
		protected internal List children;
		protected internal int depth;
		protected internal Set expectedPolicies;
		protected internal PolicyNode parent;
		protected internal Set policyQualifiers;
		protected internal string validPolicy;
		protected internal bool critical;

		/*  
		 *  
		 *  CONSTRUCTORS
		 *  
		 */ 

		public PKIXPolicyNode(List _children, int _depth, Set _expectedPolicies, PolicyNode _parent, Set _policyQualifiers, string _validPolicy, bool _critical)
		{
			children = _children;
			depth = _depth;
			expectedPolicies = _expectedPolicies;
			parent = _parent;
			policyQualifiers = _policyQualifiers;
			validPolicy = _validPolicy;
			critical = _critical;
		}

		public virtual void addChild(PKIXPolicyNode _child)
		{
			children.add(_child);
			_child.setParent(this);
		}

		public virtual Iterator getChildren()
		{
			return children.iterator();
		}

		public virtual int getDepth()
		{
			return depth;
		}

		public virtual Set getExpectedPolicies()
		{
			return expectedPolicies;
		}

		public virtual PolicyNode getParent()
		{
			return parent;
		}

		public virtual Set getPolicyQualifiers()
		{
			return policyQualifiers;
		}

		public virtual string getValidPolicy()
		{
			return validPolicy;
		}

		public virtual bool hasChildren()
		{
			return !children.isEmpty();
		}

		public virtual bool isCritical()
		{
			return critical;
		}

		public virtual void removeChild(PKIXPolicyNode _child)
		{
			children.remove(_child);
		}

		public virtual void setCritical(bool _critical)
		{
			critical = _critical;
		}

		public virtual void setParent(PKIXPolicyNode _parent)
		{
			parent = _parent;
		}

		public override string ToString()
		{
			return ToString("");
		}

		public virtual string ToString(string _indent)
		{
			StringBuffer _buf = new StringBuffer();
			_buf.append(_indent);
			_buf.append(validPolicy);
			_buf.append(" {\n");

			for (int i = 0; i < children.size(); i++)
			{
				_buf.append(((PKIXPolicyNode)children.get(i)).ToString(_indent + "    "));
			}

			_buf.append(_indent);
			_buf.append("}\n");
			return _buf.ToString();
		}

		public virtual object clone()
		{
			return copy();
		}

		public virtual PKIXPolicyNode copy()
		{
			Set _expectedPolicies = new HashSet();
			Iterator _iter = expectedPolicies.iterator();
			while (_iter.hasNext())
			{
				_expectedPolicies.add((string)_iter.next());
			}

			Set _policyQualifiers = new HashSet();
			_iter = policyQualifiers.iterator();
			while (_iter.hasNext())
			{
				_policyQualifiers.add((string)_iter.next());
			}

			PKIXPolicyNode _node = new PKIXPolicyNode(new ArrayList(), depth, _expectedPolicies, null, _policyQualifiers, validPolicy, critical);

			_iter = children.iterator();
			while (_iter.hasNext())
			{
				PKIXPolicyNode _child = ((PKIXPolicyNode)_iter.next()).copy();
				_child.setParent(_node);
				_node.addChild(_child);
			}

			return _node;
		}

		public virtual void setExpectedPolicies(Set expectedPolicies)
		{
			this.expectedPolicies = expectedPolicies;
		}
	}

}