# Migrating StackSet IAM roles from us-east-1 to us-east-2 without recreating them

You can't change the region of an existing stack instance. In StackSets, an instance is an account + region pair and is a normal regional CloudFormation stack, even when it only creates global IAM resources.

You can still move the roles without deleting and recreating them. The method is **retain + resource import**.

Placeholders: `my-iam-stackset` is the StackSet name, `iam-roles` is the new stack name in each account, `MyRole` / `my-role` are the role's logical ID and role name, and `--profile` selects the admin account or the target account.

---

## 1. Add `DeletionPolicy: Retain` and update the StackSet

In `template.yaml`, for every role:

```yaml
MyRole:
  Type: AWS::IAM::Role
  DeletionPolicy: Retain
  UpdateReplacePolicy: Retain
  Properties:
    RoleName: my-role
    ...
```

Run the update from the admin account:

```bash
aws cloudformation update-stack-set \
  --profile admin \
  --stack-set-name my-iam-stackset \
  --template-body file://template.yaml \
  --capabilities CAPABILITY_NAMED_IAM
```

Then check that the operation finished on every instance before going on:

```bash
aws cloudformation list-stack-set-operations \
  --profile admin --stack-set-name my-iam-stackset

aws cloudformation list-stack-instances \
  --profile admin --stack-set-name my-iam-stackset \
  --query 'Summaries[].[Account,Region,Status,StackInstanceStatus.DetailedStatus]' \
  --output table
```

Every instance should show `CURRENT` / `SUCCEEDED`.

> **Important:** this step must be finished on every instance before step 3. Without it, step 3 deletes the roles.

Sources:
- [DeletionPolicy](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-attribute-deletionpolicy.html)
- [update-stack-set](https://docs.aws.amazon.com/cli/latest/reference/cloudformation/update-stack-set.html)

---

## 2. Write down the stack names in us-east-1, then detach the instances and keep the stacks

```bash
aws cloudformation list-stack-instances \
  --profile admin --stack-set-name my-iam-stackset \
  --stack-instance-region us-east-1 \
  --query 'Summaries[].[Account,StackId]' --output table
```

**Self-managed:**

```bash
aws cloudformation delete-stack-instances \
  --profile admin \
  --stack-set-name my-iam-stackset \
  --regions us-east-1 \
  --accounts 111111111111 222222222222 \
  --retain-stacks
```

**Service-managed:**

```bash
aws cloudformation delete-stack-instances \
  --profile admin \
  --stack-set-name my-iam-stackset \
  --regions us-east-1 \
  --deployment-targets OrganizationalUnitIds=ou-xxxx-xxxxxxxx \
  --retain-stacks
```

Source: [delete-stack-instances](https://docs.aws.amazon.com/cli/latest/reference/cloudformation/delete-stack-instances.html). `--retain-stacks` is described as *"Removes the stack instances from the specified StackSet, but doesn't delete the stacks"*. `--accounts` is for self-managed and `--deployment-targets` is for service-managed. You can't use both.

---

## 3. Delete the standalone stacks in us-east-1 (the roles stay)

Run this in each target account:

```bash
aws cloudformation delete-stack \
  --profile account-111111111111 \
  --region us-east-1 \
  --stack-name StackSet-my-iam-stackset-xxxxxxxx

aws cloudformation wait stack-delete-complete \
  --profile account-111111111111 \
  --region us-east-1 \
  --stack-name StackSet-my-iam-stackset-xxxxxxxx

# check that the role still exists
aws iam get-role --profile account-111111111111 --role-name my-role
```

Sources:
- [delete-stack](https://docs.aws.amazon.com/cli/latest/reference/cloudformation/delete-stack.html)
- [DeletionPolicy](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-attribute-deletionpolicy.html)

---

## 4. Create a new stack in us-east-2 by importing the existing roles

Run this in each target account:

```bash
aws cloudformation create-change-set \
  --profile account-111111111111 \
  --region us-east-2 \
  --stack-name iam-roles \
  --change-set-name import \
  --change-set-type IMPORT \
  --template-body file://template.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --resources-to-import '[{"ResourceType":"AWS::IAM::Role","LogicalResourceId":"MyRole","ResourceIdentifier":{"RoleName":"my-role"}}]'

# check what will be imported
aws cloudformation describe-change-set \
  --profile account-111111111111 --region us-east-2 \
  --stack-name iam-roles --change-set-name import

aws cloudformation execute-change-set \
  --profile account-111111111111 --region us-east-2 \
  --stack-name iam-roles --change-set-name import

aws cloudformation wait stack-import-complete \
  --profile account-111111111111 --region us-east-2 \
  --stack-name iam-roles

# optional: check the template matches the real roles
aws cloudformation detect-stack-drift \
  --profile account-111111111111 --region us-east-2 \
  --stack-name iam-roles
```

For several roles, list each one in the `--resources-to-import` array, or use `--resources-to-import file://resources.json`.

Sources:
- [Creating a stack from existing resources](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/resource-import-new-stack.html): AWS's own guide for this exact case, with the same `create-change-set --change-set-type IMPORT`, `describe-change-set`, `execute-change-set` and `detect-stack-drift` commands.
- [Resource type support](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/resource-import-supported-resources.html): `AWS::IAM::Role` can be imported, `AWS::IAM::RolePolicy` cannot.
- [create-change-set](https://docs.aws.amazon.com/cli/latest/reference/cloudformation/create-change-set.html): `--capabilities` and `wait stack-import-complete` are additions not shown in AWS's import guide. The capability flag is needed for IAM resources.

---

## 5. Import the new stacks into the StackSet

Get the ARN of the new stack:

```bash
aws cloudformation describe-stacks \
  --profile account-111111111111 --region us-east-2 \
  --stack-name iam-roles --query 'Stacks[0].StackId' --output text
```

**Self-managed** (run from the admin account):

```bash
aws cloudformation import-stacks-to-stack-set \
  --profile admin \
  --stack-set-name my-iam-stackset \
  --stack-ids "arn:aws:cloudformation:us-east-2:111111111111:stack/iam-roles/..." \
              "arn:aws:cloudformation:us-east-2:222222222222:stack/iam-roles/..."
```

**Service-managed** (`--organizational-unit-ids` is required):

```bash
aws cloudformation import-stacks-to-stack-set \
  --profile admin \
  --stack-set-name my-iam-stackset \
  --stack-ids "arn:aws:cloudformation:us-east-2:111111111111:stack/iam-roles/..." \
  --organizational-unit-ids ou-xxxx-xxxxxxxx
# from a delegated admin account, add: --call-as DELEGATED_ADMIN
```

Then check:

```bash
aws cloudformation list-stack-instances \
  --profile admin --stack-set-name my-iam-stackset \
  --query 'Summaries[].[Account,Region,Status]' --output table
```

Each call takes at most 10 stack IDs inline. With `--stack-ids-url` pointing to a JSON file in S3, it takes up to 200.

Sources:
- [import-stacks-to-stack-set](https://docs.aws.amazon.com/cli/latest/reference/cloudformation/import-stacks-to-stack-set.html)
- [Self-managed import](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/self-managed-import.html)
- [Service-managed import](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/service-managed-import.html)
- [Limits](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-import.html)

---

## Watch out for

- **The import template must match the roles as they are now.** Import doesn't change the resources, so any difference shows up later as drift or as changes on the next update.
- **Role names:** if the roles have no `RoleName` set and their names were generated (e.g. `StackSet-xxx-MyRole-ABC123`), use those generated names for the import. Then put them in the template as `RoleName` so that a later update doesn't try to replace the roles.
- **Inline policies:** `AWS::IAM::RolePolicy` can't be imported. Keep policies as `Policies` inside the role.
- **Regional resources in the template** (Lambda, SNS, KMS, etc.) can't be moved this way. They have to be created again in us-east-2.
- **Service-managed:** the stacks must be in **member accounts**. A stack in the management account can't be imported.
- **Self-managed:** the target accounts need the usual StackSets admin/execution roles.
- **`NoEcho` parameters** are not supported in stack import.
- **A stack can belong to only one StackSet.**
- **With many accounts,** script steps 3–5, for example with a loop over accounts using `assume-role`.
- **Auto-deployment with service-managed permissions:** new accounts in the OU get instances in the regions where the StackSet has instances. After the migration that's only us-east-2.
- **There's no downtime.** The roles exist the whole time; only the stack that manages them changes.

### Contradiction in the docs

The `--retain-stacks` description says: *"You can't reassociate a retained stack or add an existing, saved stack to a new stack set."* This conflicts with the StackSet import docs, which allow importing existing stacks into new or existing StackSets. That sentence probably predates the import feature.

It doesn't affect this plan. You never re-import the retained us-east-1 stacks. You delete them, and you import new stacks created in us-east-2.

### Summary

Each command is in the AWS documentation. Running them together in this order is my own plan, and no AWS page covers the whole migration end to end, so **try it on one test account first**.
