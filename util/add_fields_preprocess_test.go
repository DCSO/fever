package util

import "testing"

func TestPreprocessAddedFields(t *testing.T) {
	type args struct {
		fields map[string]string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "empty fieldset",
			args: args{
				fields: map[string]string{},
			},
			want: []string{
				"}",
			},
		},
		{
			name: "fieldset present",
			args: args{
				fields: map[string]string{
					"foo": "bar",
					"baz": "quux",
				},
			},
			want: []string{
				`,"foo":"bar","baz":"quux"}`,
				`,"baz":"quux","foo":"bar"}`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PreprocessAddedFields(tt.args.fields)
			if (err != nil) != tt.wantErr {
				t.Errorf("PreprocessAddedFields() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			found := false
			for _, w := range tt.want {
				if got == w {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("PreprocessAddedFields() = %v, want %v", got, tt.want)
			}
		})
	}
}
