package util

import "testing"

func TestPreprocessAddedFields(t *testing.T) {
	type args struct {
		fields map[string]string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "empty fieldset",
			args: args{
				fields: map[string]string{},
			},
			want: "}",
		},
		{
			name: "fieldset present",
			args: args{
				fields: map[string]string{
					"foo": "bar",
					"baz": "quux",
				},
			},
			want: `,"foo":"bar","baz":"quux"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PreprocessAddedFields(tt.args.fields)
			if (err != nil) != tt.wantErr {
				t.Errorf("PreprocessAddedFields() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("PreprocessAddedFields() = %v, want %v", got, tt.want)
			}
		})
	}
}
