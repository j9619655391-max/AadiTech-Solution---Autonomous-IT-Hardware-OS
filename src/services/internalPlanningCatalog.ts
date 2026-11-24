// Explicitly synthetic example scenarios, never verified business records.
export const planningCatalog=[
  {
    "id": "M05",
    "name": "GST estimate",
    "example": {
      "lines": [
        {
          "sku": "S1",
          "quantity": 2,
          "unitPrice": "100.00",
          "gstRate": "18.00"
        }
      ],
      "discount": "10.00"
    }
  },
  {
    "id": "M13",
    "name": "Shipment packing",
    "example": {
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
    }
  },
  {
    "id": "M14",
    "name": "Payment comparison",
    "example": {
      "invoiceReference": "INV-DRAFT",
      "receiptReference": "BANK-DRAFT",
      "invoiceAmount": "100.00",
      "receivedAmount": "100.00",
      "currency": "INR"
    }
  },
  {
    "id": "M15",
    "name": "Warranty date comparison",
    "example": {
      "serialReference": "SERIAL-01",
      "declaredStart": "2026-01-01",
      "declaredEnd": "2026-12-31",
      "claimDate": "2026-06-01",
      "purchaseEvidencePresent": true
    }
  },
  {
    "id": "M18",
    "name": "Portal exposure review",
    "example": {
      "tenantReference": "TENANT-DRAFT",
      "recordKind": "QUOTE",
      "requestedFields": [
        "displayReference",
        "totalEstimate"
      ],
      "consentRecorded": true
    }
  },
  {
    "id": "M19",
    "name": "Partner price protection",
    "example": {
      "partnerReference": "P1",
      "sku": "SKU1",
      "requestedPrice": "120",
      "minimumPrice": "100",
      "startsOn": "2026-01-01",
      "endsOn": "2026-01-31"
    }
  },
  {
    "id": "M20",
    "name": "Commission estimate",
    "example": {
      "partnerReference": "P1",
      "collected": "1000",
      "refunds": "100",
      "rate": "10",
      "cap": "100"
    }
  },
  {
    "id": "M21",
    "name": "Consent screening",
    "example": {
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
    }
  },
  {
    "id": "M22",
    "name": "AI action screening",
    "example": {
      "action": "DRAFT",
      "targetReference": "T1",
      "humanReviewRequested": true
    }
  },
  {
    "id": "M23",
    "name": "Demand scenario",
    "example": {
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
    }
  },
  {
    "id": "M24",
    "name": "Workflow retry planning",
    "example": {
      "jobReference": "JOB1",
      "attempt": 2,
      "maxAttempts": 5,
      "lastResult": "TRANSIENT_FAILURE",
      "idempotencyReference": "KEY1",
      "baseDelaySeconds": 30
    }
  },
  {
    "id": "M25",
    "name": "Knowledge source screening",
    "example": {
      "documentReference": "DOC1",
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "rights": "DECLARED_OWNED",
      "scope": "INTERNAL",
      "requestedScope": "INTERNAL",
      "containsPersonalData": false
    }
  }
];
export const planningTabs:Record<string,readonly string[]>={finance:['M05','M14','M15'],orders:['M13'],portals:['M18','M19','M20'],marketing:['M21','M22'],analytics:['M23'],workflows:['M24','M25']};
