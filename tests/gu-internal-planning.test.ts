import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {evaluateInternalPlan,GU_MODULES} from '../server/internalPlanning/planners';
import {PlanningInputError} from '../server/internalPlanning/validation';
type Scenario=[string,Record<string,unknown>,string|Record<string,unknown>];
const suites:{id:string;name:string;base:Record<string,unknown>;cases:Scenario[]}[]=[
  {
    "id": "M05",
    "name": "GST estimate",
    "base": {
      "lines": [
        {
          "sku": "S1",
          "quantity": 2,
          "unitPrice": "100.00",
          "gstRate": "18.00"
        }
      ],
      "discount": "10.00"
    },
    "cases": [
      [
        "tax estimate",
        {},
        {
          "estimatedTotal": "224.20",
          "estimatedTax": "34.20"
        }
      ],
      [
        "zero discount",
        {
          "discount": "0"
        },
        {
          "estimatedTotal": "236.00"
        }
      ],
      [
        "full discount",
        {
          "discount": "200"
        },
        {
          "estimatedTotal": "0.00"
        }
      ],
      [
        "excess discount",
        {
          "discount": "201"
        },
        "DISCOUNT_EXCEEDS_SUBTOTAL"
      ],
      [
        "invalid rate",
        {
          "lines": [
            {
              "sku": "S1",
              "quantity": 1,
              "unitPrice": "10",
              "gstRate": "101"
            }
          ]
        },
        "INVALID_RATE"
      ],
      [
        "quantity zero",
        {
          "lines": [
            {
              "sku": "S1",
              "quantity": 0,
              "unitPrice": "10",
              "gstRate": "18"
            }
          ]
        },
        "INVALID_INTEGER"
      ],
      [
        "duplicate SKU",
        {
          "lines": [
            {
              "sku": "S1",
              "quantity": 1,
              "unitPrice": "10",
              "gstRate": "18"
            },
            {
              "sku": "S1",
              "quantity": 1,
              "unitPrice": "20",
              "gstRate": "5"
            }
          ]
        },
        "DUPLICATE_REFERENCE"
      ],
      [
        "floating money",
        {
          "discount": 10
        },
        "INVALID_MONEY"
      ],
      [
        "empty lines",
        {
          "lines": []
        },
        "INVALID_ARRAY"
      ],
      [
        "unexpected authority",
        {
          "approved": true
        },
        "INVALID_FIELDS"
      ]
    ]
  },
  {
    "id": "M13",
    "name": "Shipment packing",
    "base": {
      "orderReference": "SO-DRAFT",
      "items": [
        {
          "sku": "S1",
          "ordered": 4,
          "packed": 2
        }
      ],
      "packages": 1,
      "destinationPostalCode": "400001"
    },
    "cases": [
      [
        "partial packing",
        {},
        {
          "ordered": 4,
          "packed": 2,
          "remaining": 2,
          "packingComplete": false
        }
      ],
      [
        "complete packing",
        {
          "items": [
            {
              "sku": "S1",
              "ordered": 4,
              "packed": 4
            }
          ]
        },
        {
          "packingComplete": true,
          "remaining": 0
        }
      ],
      [
        "zero packing",
        {
          "items": [
            {
              "sku": "S1",
              "ordered": 4,
              "packed": 0
            }
          ],
          "packages": 0
        },
        {
          "packed": 0
        }
      ],
      [
        "overpacked",
        {
          "items": [
            {
              "sku": "S1",
              "ordered": 4,
              "packed": 5
            }
          ]
        },
        "OVERPACKED"
      ],
      [
        "packages without stock",
        {
          "items": [
            {
              "sku": "S1",
              "ordered": 4,
              "packed": 0
            }
          ]
        },
        "PACKAGE_COUNT_CONFLICT"
      ],
      [
        "too many packages",
        {
          "packages": 3
        },
        "PACKAGE_COUNT_CONFLICT"
      ],
      [
        "invalid postal",
        {
          "destinationPostalCode": "000001"
        },
        "INVALID_POSTAL_CODE"
      ],
      [
        "invalid order reference",
        {
          "orderReference": "../SO"
        },
        "INVALID_REFERENCE"
      ],
      [
        "duplicate item",
        {
          "items": [
            {
              "sku": "S1",
              "ordered": 4,
              "packed": 2
            },
            {
              "sku": "S1",
              "ordered": 1,
              "packed": 0
            }
          ]
        },
        "DUPLICATE_REFERENCE"
      ],
      [
        "unexpected dispatch",
        {
          "dispatch": true
        },
        "INVALID_FIELDS"
      ]
    ]
  },
  {
    "id": "M14",
    "name": "Payment comparison",
    "base": {
      "invoiceReference": "INV-DRAFT",
      "receiptReference": "BANK-DRAFT",
      "invoiceAmount": "100.00",
      "receivedAmount": "100.00",
      "currency": "INR"
    },
    "cases": [
      [
        "exact",
        {},
        {
          "comparison": "EXACT",
          "unmatchedAmount": "0.00"
        }
      ],
      [
        "short",
        {
          "receivedAmount": "98.99"
        },
        {
          "comparison": "SHORT",
          "unmatchedAmount": "1.01"
        }
      ],
      [
        "excess",
        {
          "receivedAmount": "100.01"
        },
        {
          "comparison": "EXCESS",
          "unmatchedAmount": "0.01"
        }
      ],
      [
        "zero receipt",
        {
          "receivedAmount": "0"
        },
        {
          "comparison": "SHORT",
          "unmatchedAmount": "100.00"
        }
      ],
      [
        "zero invoice",
        {
          "invoiceAmount": "0"
        },
        "ZERO_INVOICE"
      ],
      [
        "negative receipt",
        {
          "receivedAmount": "-1"
        },
        "INVALID_MONEY"
      ],
      [
        "fractional paise",
        {
          "receivedAmount": "1.001"
        },
        "INVALID_MONEY"
      ],
      [
        "unsupported currency",
        {
          "currency": "USD"
        },
        "INVALID_ENUM"
      ],
      [
        "invalid receipt reference",
        {
          "receiptReference": "bank ref"
        },
        "INVALID_REFERENCE"
      ],
      [
        "forged settlement",
        {
          "settled": true
        },
        "INVALID_FIELDS"
      ]
    ]
  },
  {
    "id": "M15",
    "name": "Warranty date comparison",
    "base": {
      "serialReference": "SERIAL-01",
      "declaredStart": "2026-01-01",
      "declaredEnd": "2026-12-31",
      "claimDate": "2026-06-01",
      "purchaseEvidencePresent": true
    },
    "cases": [
      [
        "within",
        {},
        {
          "declaredDateComparison": "WITHIN_DECLARED_INTERVAL"
        }
      ],
      [
        "before",
        {
          "claimDate": "2025-12-31"
        },
        {
          "declaredDateComparison": "BEFORE_START"
        }
      ],
      [
        "after",
        {
          "claimDate": "2027-01-01"
        },
        {
          "declaredDateComparison": "AFTER_END"
        }
      ],
      [
        "inclusive end",
        {
          "claimDate": "2026-12-31"
        },
        {
          "declaredDateComparison": "WITHIN_DECLARED_INTERVAL"
        }
      ],
      [
        "missing receipt",
        {
          "purchaseEvidencePresent": false
        },
        {
          "purchaseEvidencePresent": false
        }
      ],
      [
        "bad calendar",
        {
          "claimDate": "2026-02-30"
        },
        "INVALID_DATE"
      ],
      [
        "reversed period",
        {
          "declaredEnd": "2025-12-31"
        },
        "INVALID_COVERAGE_INTERVAL"
      ],
      [
        "excessive period",
        {
          "declaredEnd": "2040-01-01"
        },
        "INVALID_COVERAGE_INTERVAL"
      ],
      [
        "boolean type",
        {
          "purchaseEvidencePresent": "true"
        },
        "INVALID_BOOLEAN"
      ],
      [
        "forged OEM",
        {
          "oemVerified": true
        },
        "INVALID_FIELDS"
      ]
    ]
  },
  {
    "id": "M18",
    "name": "Portal exposure review",
    "base": {
      "tenantReference": "TENANT-DRAFT",
      "recordKind": "QUOTE",
      "requestedFields": [
        "displayReference",
        "totalEstimate"
      ],
      "consentRecorded": true
    },
    "cases": [
      [
        "quote projection",
        {},
        {
          "recordKind": "QUOTE",
          "proposedFields": [
            "displayReference",
            "totalEstimate"
          ]
        }
      ],
      [
        "order projection",
        {
          "recordKind": "ORDER",
          "requestedFields": [
            "quantity"
          ]
        },
        {
          "recordKind": "ORDER"
        }
      ],
      [
        "ticket projection",
        {
          "recordKind": "TICKET",
          "requestedFields": [
            "supportReference"
          ]
        },
        {
          "recordKind": "TICKET"
        }
      ],
      [
        "no consent",
        {
          "consentRecorded": false
        },
        {
          "blockers": [
            "CONSENT_NOT_RECORDED",
            "TENANT_SCOPE_SSO_AND_ISSUED_RECORD_VERIFICATION_REQUIRED"
          ]
        }
      ],
      [
        "scope mismatched field",
        {
          "recordKind": "TICKET"
        },
        "FIELD_NOT_ALLOWED_FOR_KIND"
      ],
      [
        "private field",
        {
          "requestedFields": [
            "passwordHash"
          ]
        },
        "INVALID_ENUM"
      ],
      [
        "duplicate fields",
        {
          "requestedFields": [
            "status",
            "status"
          ]
        },
        "DUPLICATE_REFERENCE"
      ],
      [
        "empty fields",
        {
          "requestedFields": []
        },
        "INVALID_ARRAY"
      ],
      [
        "invalid tenant",
        {
          "tenantReference": "../../private"
        },
        "INVALID_REFERENCE"
      ],
      [
        "forged access",
        {
          "authorized": true
        },
        "INVALID_FIELDS"
      ]
    ]
  },
  {
    "id": "M19",
    "name": "Partner price protection",
    "base": {
      "partnerReference": "P1",
      "sku": "SKU1",
      "requestedPrice": "120",
      "minimumPrice": "100",
      "startsOn": "2026-01-01",
      "endsOn": "2026-01-31"
    },
    "cases": [
      [
        "above floor",
        {},
        {
          "priceComparison": "AT_OR_ABOVE_DECLARED_FLOOR",
          "days": 31
        }
      ],
      [
        "at floor",
        {
          "requestedPrice": "100"
        },
        {
          "priceComparison": "AT_OR_ABOVE_DECLARED_FLOOR"
        }
      ],
      [
        "below floor",
        {
          "requestedPrice": "99.99"
        },
        {
          "priceComparison": "BELOW_DECLARED_FLOOR"
        }
      ],
      [
        "single day",
        {
          "endsOn": "2026-01-01"
        },
        {
          "days": 1
        }
      ],
      [
        "zero floor",
        {
          "minimumPrice": "0"
        },
        "ZERO_PRICE"
      ],
      [
        "zero requested",
        {
          "requestedPrice": "0"
        },
        "ZERO_PRICE"
      ],
      [
        "reversed",
        {
          "endsOn": "2025-12-31"
        },
        "INVALID_PROTECTION_INTERVAL"
      ],
      [
        "excess period",
        {
          "endsOn": "2026-05-01"
        },
        "INVALID_PROTECTION_INTERVAL"
      ],
      [
        "bad SKU",
        {
          "sku": "sku /1"
        },
        "INVALID_REFERENCE"
      ],
      [
        "forged price lock",
        {
          "locked": true
        },
        "INVALID_FIELDS"
      ]
    ]
  },
  {
    "id": "M20",
    "name": "Commission estimate",
    "base": {
      "partnerReference": "P1",
      "collected": "1000",
      "refunds": "100",
      "rate": "10",
      "cap": "100"
    },
    "cases": [
      [
        "net basis",
        {},
        {
          "declaredNetCollections": "900.00",
          "cappedEstimate": "90.00",
          "capApplied": false
        }
      ],
      [
        "cap",
        {
          "cap": "50"
        },
        {
          "cappedEstimate": "50.00",
          "capApplied": true
        }
      ],
      [
        "full refund",
        {
          "refunds": "1000"
        },
        {
          "cappedEstimate": "0.00"
        }
      ],
      [
        "zero rate",
        {
          "rate": "0"
        },
        {
          "cappedEstimate": "0.00"
        }
      ],
      [
        "half-up rounding",
        {
          "collected": "0.05",
          "refunds": "0",
          "rate": "10"
        },
        {
          "cappedEstimate": "0.01"
        }
      ],
      [
        "refund exceeds",
        {
          "refunds": "1001"
        },
        "REFUNDS_EXCEED_COLLECTION"
      ],
      [
        "rate exceeds",
        {
          "rate": "101"
        },
        "INVALID_RATE"
      ],
      [
        "negative cap",
        {
          "cap": "-1"
        },
        "INVALID_MONEY"
      ],
      [
        "bad partner",
        {
          "partnerReference": ""
        },
        "INVALID_TEXT"
      ],
      [
        "forged payout",
        {
          "paid": true
        },
        "INVALID_FIELDS"
      ]
    ]
  },
  {
    "id": "M21",
    "name": "Consent screening",
    "base": {
      "channel": "EMAIL",
      "asOf": "2026-06-01",
      "recipients": [
        {
          "contactReference": "C1",
          "consentChannel": "EMAIL",
          "consentedOn": "2026-01-01",
          "expiresOn": "2026-12-31",
          "optedOut": false
        }
      ]
    },
    "cases": [
      [
        "declared match",
        {},
        {
          "declaredMatchCount": 1
        }
      ],
      [
        "opt-out",
        {
          "recipients": [
            {
              "contactReference": "C1",
              "consentChannel": "EMAIL",
              "consentedOn": "2026-01-01",
              "expiresOn": "2026-12-31",
              "optedOut": true
            }
          ]
        },
        {
          "declaredMatchCount": 0
        }
      ],
      [
        "channel mismatch",
        {
          "channel": "WHATSAPP"
        },
        {
          "declaredMatchCount": 0
        }
      ],
      [
        "expired",
        {
          "asOf": "2027-01-01"
        },
        {
          "declaredMatchCount": 0
        }
      ],
      [
        "future consent",
        {
          "asOf": "2025-12-31"
        },
        {
          "declaredMatchCount": 0
        }
      ],
      [
        "inclusive expiry",
        {
          "asOf": "2026-12-31"
        },
        {
          "declaredMatchCount": 1
        }
      ],
      [
        "unsupported channel",
        {
          "channel": "SMS"
        },
        "INVALID_ENUM"
      ],
      [
        "bad as of",
        {
          "asOf": "2026-02-30"
        },
        "INVALID_DATE"
      ],
      [
        "empty recipient",
        {
          "recipients": []
        },
        "INVALID_ARRAY"
      ],
      [
        "forged send",
        {
          "dispatch": true
        },
        "INVALID_FIELDS"
      ]
    ]
  },
  {
    "id": "M22",
    "name": "AI action screening",
    "base": {
      "action": "DRAFT",
      "targetReference": "T1",
      "humanReviewRequested": true
    },
    "cases": [
      [
        "draft",
        {},
        {
          "classification": "DRAFT_REVIEW_ONLY"
        }
      ],
      [
        "summary",
        {
          "action": "READ_SUMMARY"
        },
        {
          "classification": "DRAFT_REVIEW_ONLY"
        }
      ],
      [
        "send",
        {
          "action": "SEND"
        },
        {
          "classification": "EXTERNAL_ACTION_BLOCKED"
        }
      ],
      [
        "pay",
        {
          "action": "PAY"
        },
        {
          "classification": "EXTERNAL_ACTION_BLOCKED"
        }
      ],
      [
        "stock",
        {
          "action": "STOCK_POST"
        },
        {
          "classification": "EXTERNAL_ACTION_BLOCKED"
        }
      ],
      [
        "document",
        {
          "action": "ISSUE_DOCUMENT"
        },
        {
          "classification": "EXTERNAL_ACTION_BLOCKED"
        }
      ],
      [
        "command",
        {
          "action": "EXECUTE_COMMAND"
        },
        {
          "classification": "EXTERNAL_ACTION_BLOCKED"
        }
      ],
      [
        "unknown action",
        {
          "action": "RAW_SQL"
        },
        "INVALID_ENUM"
      ],
      [
        "invalid review",
        {
          "humanReviewRequested": 1
        },
        "INVALID_BOOLEAN"
      ],
      [
        "forged authority",
        {
          "approved": true
        },
        "INVALID_FIELDS"
      ]
    ]
  },
  {
    "id": "M23",
    "name": "Demand scenario",
    "base": {
      "observations": [
        {
          "month": "2026-01",
          "units": 1
        },
        {
          "month": "2026-02",
          "units": 2
        },
        {
          "month": "2026-03",
          "units": 4
        }
      ],
      "horizon": 2
    },
    "cases": [
      [
        "mean",
        {},
        {
          "scenarioUnitsPerMonth": 2,
          "scenarioTotalUnits": 4
        }
      ],
      [
        "three months",
        {
          "horizon": 3
        },
        {
          "scenarioTotalUnits": 6
        }
      ],
      [
        "zero history",
        {
          "observations": [
            {
              "month": "2026-01",
              "units": 0
            },
            {
              "month": "2026-02",
              "units": 0
            },
            {
              "month": "2026-03",
              "units": 0
            }
          ]
        },
        {
          "scenarioUnitsPerMonth": 0
        }
      ],
      [
        "year rollover",
        {
          "observations": [
            {
              "month": "2025-12",
              "units": 1
            },
            {
              "month": "2026-01",
              "units": 2
            },
            {
              "month": "2026-02",
              "units": 5
            }
          ]
        },
        {
          "scenarioUnitsPerMonth": 3
        }
      ],
      [
        "missing month",
        {
          "observations": [
            {
              "month": "2026-01",
              "units": 1
            },
            {
              "month": "2026-03",
              "units": 2
            },
            {
              "month": "2026-04",
              "units": 4
            }
          ]
        },
        "NONCONTIGUOUS_HISTORY"
      ],
      [
        "bad month",
        {
          "observations": [
            {
              "month": "2026-00",
              "units": 1
            },
            {
              "month": "2026-01",
              "units": 2
            },
            {
              "month": "2026-02",
              "units": 4
            }
          ]
        },
        "INVALID_MONTH"
      ],
      [
        "negative units",
        {
          "observations": [
            {
              "month": "2026-01",
              "units": -1
            },
            {
              "month": "2026-02",
              "units": 2
            },
            {
              "month": "2026-03",
              "units": 4
            }
          ]
        },
        "INVALID_INTEGER"
      ],
      [
        "bad horizon",
        {
          "horizon": 4
        },
        "INVALID_INTEGER"
      ],
      [
        "insufficient history",
        {
          "observations": [
            {
              "month": "2026-01",
              "units": 1
            }
          ]
        },
        "INVALID_ARRAY"
      ],
      [
        "forged measurement",
        {
          "validated": true
        },
        "INVALID_FIELDS"
      ]
    ]
  },
  {
    "id": "M24",
    "name": "Workflow retry planning",
    "base": {
      "jobReference": "JOB1",
      "attempt": 2,
      "maxAttempts": 5,
      "lastResult": "TRANSIENT_FAILURE",
      "idempotencyReference": "KEY1",
      "baseDelaySeconds": 30
    },
    "cases": [
      [
        "transient",
        {},
        {
          "classification": "REVIEW_RETRY",
          "scenarioDelaySeconds": 60
        }
      ],
      [
        "max attempts",
        {
          "attempt": 5
        },
        {
          "classification": "NO_RETRY",
          "scenarioDelaySeconds": null
        }
      ],
      [
        "permanent",
        {
          "lastResult": "PERMANENT_FAILURE"
        },
        {
          "classification": "NO_RETRY"
        }
      ],
      [
        "success",
        {
          "lastResult": "SUCCESS"
        },
        {
          "classification": "NO_RETRY"
        }
      ],
      [
        "ambiguous commit",
        {
          "lastResult": "UNKNOWN_COMMIT"
        },
        {
          "classification": "RECONCILE_BEFORE_RETRY"
        }
      ],
      [
        "delay cap",
        {
          "attempt": 9,
          "maxAttempts": 10,
          "baseDelaySeconds": 300
        },
        {
          "scenarioDelaySeconds": 3600
        }
      ],
      [
        "attempt conflict",
        {
          "attempt": 6
        },
        "ATTEMPT_LIMIT_CONFLICT"
      ],
      [
        "zero delay",
        {
          "baseDelaySeconds": 0
        },
        "INVALID_INTEGER"
      ],
      [
        "invalid key",
        {
          "idempotencyReference": "bad key"
        },
        "INVALID_REFERENCE"
      ],
      [
        "forged execution",
        {
          "runNow": true
        },
        "INVALID_FIELDS"
      ]
    ]
  },
  {
    "id": "M25",
    "name": "Knowledge source screening",
    "base": {
      "documentReference": "DOC1",
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "rights": "DECLARED_OWNED",
      "scope": "INTERNAL",
      "requestedScope": "INTERNAL",
      "containsPersonalData": false
    },
    "cases": [
      [
        "declared same scope",
        {},
        {
          "declaredScope": "INTERNAL",
          "requestedScope": "INTERNAL",
          "blockers": [
            "SOURCE_RIGHTS_AND_ACCESS_AUTHORITY_REQUIRED"
          ]
        }
      ],
      [
        "scope narrowing",
        {
          "requestedScope": "RESTRICTED"
        },
        {
          "requestedScope": "RESTRICTED"
        }
      ],
      [
        "scope widening",
        {
          "requestedScope": "PUBLIC"
        },
        {
          "blockers": [
            "SOURCE_RIGHTS_AND_ACCESS_AUTHORITY_REQUIRED",
            "SCOPE_WIDENING_BLOCKED"
          ]
        }
      ],
      [
        "unknown rights",
        {
          "rights": "UNKNOWN"
        },
        {
          "blockers": [
            "SOURCE_RIGHTS_AND_ACCESS_AUTHORITY_REQUIRED",
            "RIGHTS_NOT_ESTABLISHED"
          ]
        }
      ],
      [
        "prohibited rights",
        {
          "rights": "PROHIBITED"
        },
        {
          "blockers": [
            "SOURCE_RIGHTS_AND_ACCESS_AUTHORITY_REQUIRED",
            "RIGHTS_NOT_ESTABLISHED"
          ]
        }
      ],
      [
        "personal data",
        {
          "containsPersonalData": true
        },
        {
          "blockers": [
            "SOURCE_RIGHTS_AND_ACCESS_AUTHORITY_REQUIRED",
            "PERSONAL_DATA_REVIEW_REQUIRED"
          ]
        }
      ],
      [
        "bad digest",
        {
          "sha256": "ABC"
        },
        "INVALID_DIGEST"
      ],
      [
        "bad scope",
        {
          "scope": "ALL"
        },
        "INVALID_ENUM"
      ],
      [
        "bad reference",
        {
          "documentReference": "../doc"
        },
        "INVALID_REFERENCE"
      ],
      [
        "forged ingestion",
        {
          "ingest": true
        },
        "INVALID_FIELDS"
      ]
    ]
  }
];
for(const suite of suites)for(const [index,[name,patch,expected]] of suite.cases.entries()){
 test('1GU '+suite.id+'-'+String(index+1).padStart(2,'0')+' '+name,()=>{
  const input={...suite.base,...patch};
  if(typeof expected==='string'){
   assert.throws(()=>evaluateInternalPlan(suite.id,input),(e:unknown)=>e instanceof PlanningInputError&&e.code===expected);
  }else{
   const result=evaluateInternalPlan(suite.id,input) as Record<string,unknown>;
   for(const [field,value] of Object.entries(expected))assert.deepEqual(result[field],value,field);
   assert.equal(result.module,suite.id);assert.equal(result.releaseDecision,'HOLD');
   assert.equal(result.evidenceStatus,'OPERATOR_SUPPLIED_UNVERIFIED');
   assert.equal(result.productionReleaseAuthorized,false);assert.equal(result.externalExecutionEnabled,false);
   assert.equal(result.requiresHumanReview,true);
  }
 });
}
test('1GU exact twelve-module scope and unsupported module denial',()=>{
 assert.deepEqual(GU_MODULES,suites.map(x=>x.id));
 for(const bad of ['M01','M30','__proto__','constructor',null])assert.throws(()=>evaluateInternalPlan(bad,{}),/UNSUPPORTED_MODULE/);
});
test('1GU rejects accessor, inherited and sparse inputs without invoking getters',()=>{
 let invoked=false;
 const obj=Object.defineProperty({...suites[0].base},'discount',{enumerable:true,get(){invoked=true;return '0';}});
 assert.throws(()=>evaluateInternalPlan('M05',obj),/INVALID_FIELDS/);assert.equal(invoked,false);
 assert.throws(()=>evaluateInternalPlan('M05',Object.create(suites[0].base)),/INVALID_OBJECT/);
 assert.throws(()=>evaluateInternalPlan('M05',{...suites[0].base,lines:Array(1)}),/INVALID_ARRAY/);
});
test('1GU route mounted behind actual OWNER guard and no-store, no database/provider import',()=>{
 const route=readFileSync('server/internalPlanning/router.ts','utf8'),app=readFileSync('server.ts','utf8'),logic=readFileSync('server/internalPlanning/planners.ts','utf8');
 assert.match(app,/app\.use\("\/api\/internal-planning",internalPlanningRouter\)/);
 assert.ok(route.indexOf('router.use(requireOwner)')<route.indexOf("router.post('/:module'"));
 assert.match(route,/Cache-Control','no-store/);
 assert.doesNotMatch(logic,/from ['"].*(?:db|provider|dispatch|journal)/);
});
